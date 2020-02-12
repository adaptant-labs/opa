// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package logs implements decision log buffering and uploading.
package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	minimizers "github.com/adaptant-labs/go-minimizer"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/plugins/rest"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/server"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/util"
)

// Logger defines the interface for decision logging plugins.
type Logger interface {
	plugins.Plugin

	Log(context.Context, EventV1) error
}

// EventV1 represents a decision log event.
type EventV1 struct {
	Labels      map[string]string       `json:"labels"`
	DecisionID  string                  `json:"decision_id"`
	Revision    string                  `json:"revision,omitempty"` // Deprecated: Use Bundles instead
	Bundles     map[string]BundleInfoV1 `json:"bundles,omitempty"`
	Path        string                  `json:"path,omitempty"`
	Query       string                  `json:"query,omitempty"`
	Input       *interface{}            `json:"input,omitempty"`
	Result      *interface{}            `json:"result,omitempty"`
	Erased      []string                `json:"erased,omitempty"`
	Error       error                   `json:"error,omitempty"`
	RequestedBy string                  `json:"requested_by"`
	Timestamp   time.Time               `json:"timestamp"`
	Metrics     map[string]interface{}  `json:"metrics,omitempty"`
}

// BundleInfoV1 describes a bundle associated with a decision log event.
type BundleInfoV1 struct {
	Revision string `json:"revision,omitempty"`
}

const (
	// min amount of time to wait following a failure
	minRetryDelay               = time.Millisecond * 100
	defaultMinDelaySeconds      = int64(300)
	defaultMaxDelaySeconds      = int64(600)
	defaultUploadSizeLimitBytes = int64(32768) // 32KB limit
	defaultBufferSizeLimitBytes = int64(0)     // unlimited
	defaultExcludeDecisionPath  = "/system/log/exclude"
	defaultMaskDecisionPath     = "/system/log/mask"
	defaultMinimizeDecisionPath = "/system/log/minimize"
	defaultTokenizeDecisionPath = "/system/log/tokenize"
	defaultMinimizationLevel    = minimizers.MinimizationFine
)

// ReportingConfig represents configuration for the plugin's reporting behaviour.
type ReportingConfig struct {
	BufferSizeLimitBytes *int64 `json:"buffer_size_limit_bytes,omitempty"` // max size of in-memory buffer
	UploadSizeLimitBytes *int64 `json:"upload_size_limit_bytes,omitempty"` // max size of upload payload
	MinDelaySeconds      *int64 `json:"min_delay_seconds,omitempty"`       // min amount of time to wait between successful poll attempts
	MaxDelaySeconds      *int64 `json:"max_delay_seconds,omitempty"`       // max amount of time to wait between poll attempts
}

// Config represents the plugin configuration.
type Config struct {
	Plugin        *string         `json:"plugin"`
	Service       string          `json:"service"`
	PartitionName string          `json:"partition_name,omitempty"`
	Reporting     ReportingConfig `json:"reporting"`
	ExcludeDecision *string       `json:"exclude_decision"`
	MaskDecision  *string         `json:"mask_decision"`
	MinimizeDecision *string      `json:"minimize_decision"`
	TokenizeDecision *string      `json:"tokenize_decision"`
	ConsoleLogs   bool            `json:"console"`

	MinimizationLevel minimizers.MinimizationLevel `json:"minimization_level"`

	excludeDecisionRef  ast.Ref
	maskDecisionRef     ast.Ref
	minimizeDecisionRef ast.Ref
	tokenizeDecisionRef ast.Ref
}

func (c *Config) validateAndInjectDefaults(services []string, plugins []string) error {

	if c.Plugin != nil {
		var found bool
		for _, other := range plugins {
			if other == *c.Plugin {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid plugin name %q in decision_logs", *c.Plugin)
		}
	} else if c.Service == "" && len(services) != 0 && !c.ConsoleLogs {
		// For backwards compatibility allow defaulting to the first
		// service listed, but only if console logging is disabled. If enabled
		// we can't tell if the deployer wanted to use only console logs or
		// both console logs and the default service option.
		c.Service = services[0]
	} else if c.Service != "" {
		found := false

		for _, svc := range services {
			if svc == c.Service {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("invalid service name %q in decision_logs", c.Service)
		}
	}

	if c.Plugin == nil && c.Service == "" && !c.ConsoleLogs {
		return fmt.Errorf("invalid decision_log config, must have a `service`, `plugin`, or `console` logging enabled")
	}

	min := defaultMinDelaySeconds
	max := defaultMaxDelaySeconds

	// reject bad min/max values
	if c.Reporting.MaxDelaySeconds != nil && c.Reporting.MinDelaySeconds != nil {
		if *c.Reporting.MaxDelaySeconds < *c.Reporting.MinDelaySeconds {
			return fmt.Errorf("max reporting delay must be >= min reporting delay in decision_logs")
		}
		min = *c.Reporting.MinDelaySeconds
		max = *c.Reporting.MaxDelaySeconds
	} else if c.Reporting.MaxDelaySeconds == nil && c.Reporting.MinDelaySeconds != nil {
		return fmt.Errorf("reporting configuration missing 'max_delay_seconds' in decision_logs")
	} else if c.Reporting.MinDelaySeconds == nil && c.Reporting.MaxDelaySeconds != nil {
		return fmt.Errorf("reporting configuration missing 'min_delay_seconds' in decision_logs")
	}

	// scale to seconds
	minSeconds := int64(time.Duration(min) * time.Second)
	c.Reporting.MinDelaySeconds = &minSeconds

	maxSeconds := int64(time.Duration(max) * time.Second)
	c.Reporting.MaxDelaySeconds = &maxSeconds

	// default the upload size limit
	uploadLimit := defaultUploadSizeLimitBytes
	if c.Reporting.UploadSizeLimitBytes != nil {
		uploadLimit = *c.Reporting.UploadSizeLimitBytes
	}

	c.Reporting.UploadSizeLimitBytes = &uploadLimit

	// default the buffer size limit
	bufferLimit := defaultBufferSizeLimitBytes
	if c.Reporting.BufferSizeLimitBytes != nil {
		bufferLimit = *c.Reporting.BufferSizeLimitBytes
	}

	c.Reporting.BufferSizeLimitBytes = &bufferLimit

	if c.ExcludeDecision == nil {
		excludeDecision := defaultExcludeDecisionPath
		c.ExcludeDecision = &excludeDecision
	}

	if c.MaskDecision == nil {
		maskDecision := defaultMaskDecisionPath
		c.MaskDecision = &maskDecision
	}

	if c.MinimizeDecision == nil {
		minimizeDecision := defaultMinimizeDecisionPath
		c.MinimizeDecision = &minimizeDecision
	}

	if c.TokenizeDecision == nil {
		tokenizeDecision := defaultTokenizeDecisionPath
		c.TokenizeDecision = &tokenizeDecision
	}

	if c.MinimizationLevel == minimizers.MinimizationNone {
		c.MinimizationLevel = defaultMinimizationLevel
	}

	var err error
	c.excludeDecisionRef, err = parsePathToRef(*c.ExcludeDecision)
	if err != nil {
		return errors.Wrap(err, "invalid exclude_decision in decision_logs")
	}

	c.maskDecisionRef, err = parsePathToRef(*c.MaskDecision)
	if err != nil {
		return errors.Wrap(err, "invalid mask_decision in decision_logs")
	}

	c.minimizeDecisionRef, err = parsePathToRef(*c.MinimizeDecision)
	if err != nil {
		return errors.Wrap(err, "invalid minimize_decision in decision_logs")
	}

	c.tokenizeDecisionRef, err = parsePathToRef(*c.TokenizeDecision)
	if err != nil {
		return errors.Wrap(err, "invalid tokenize_decision in decision_logs")
	}

	return nil
}

func parsePathToRef(s string) (ast.Ref, error) {
	s = strings.Replace(strings.Trim(s, "/"), "/", ".", -1)
	return ast.ParseRef("data." + s)
}

// Plugin implements decision log buffering and uploading.
type Plugin struct {
	manager   *plugins.Manager
	config    Config
	buffer    *logBuffer
	enc       *chunkEncoder
	mtx       sync.Mutex
	stop      chan chan struct{}
	reconfig  chan reconfigure
	exclude   *rego.PreparedEvalQuery
	mask      *rego.PreparedEvalQuery
	minimize  *rego.PreparedEvalQuery
	tokenize  *rego.PreparedEvalQuery
	maskMutex sync.Mutex
}

type reconfigure struct {
	config interface{}
	done   chan struct{}
}

// ParseConfig validates the config and injects default values.
func ParseConfig(config []byte, services []string, plugins []string) (*Config, error) {
	if config == nil {
		return nil, nil
	}

	var parsedConfig Config

	if err := util.Unmarshal(config, &parsedConfig); err != nil {
		return nil, err
	}

	if err := parsedConfig.validateAndInjectDefaults(services, plugins); err != nil {
		return nil, err
	}

	return &parsedConfig, nil
}

// New returns a new Plugin with the given config.
func New(parsedConfig *Config, manager *plugins.Manager) *Plugin {

	plugin := &Plugin{
		manager:  manager,
		config:   *parsedConfig,
		stop:     make(chan chan struct{}),
		buffer:   newLogBuffer(*parsedConfig.Reporting.BufferSizeLimitBytes),
		enc:      newChunkEncoder(*parsedConfig.Reporting.UploadSizeLimitBytes),
		reconfig: make(chan reconfigure),
	}

	manager.RegisterCompilerTrigger(plugin.compilerUpdated)

	manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateNotReady})

	return plugin
}

// Name identifies the plugin on manager.
const Name = "decision_logs"

// Lookup returns the decision logs plugin registered with the manager.
func Lookup(manager *plugins.Manager) *Plugin {
	if p := manager.Plugin(Name); p != nil {
		return p.(*Plugin)
	}
	return nil
}

// Start starts the plugin.
func (p *Plugin) Start(ctx context.Context) error {
	p.logInfo("Starting decision logger.")
	go p.loop()
	p.manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateOK})
	return nil
}

// Stop stops the plugin.
func (p *Plugin) Stop(ctx context.Context) {
	p.logInfo("Stopping decision logger.")
	done := make(chan struct{})
	p.stop <- done
	_ = <-done
	p.manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateNotReady})
}

// Log appends a decision log event to the buffer for uploading.
func (p *Plugin) Log(ctx context.Context, decision *server.Info) error {

	bundles := map[string]BundleInfoV1{}
	for name, info := range decision.Bundles {
		bundles[name] = BundleInfoV1{Revision: info.Revision}
	}

	event := EventV1{
		Labels:      p.manager.Labels(),
		DecisionID:  decision.DecisionID,
		Revision:    decision.Revision,
		Bundles:     bundles,
		Path:        decision.Path,
		Query:       decision.Query,
		Input:       decision.Input,
		Result:      decision.Results,
		RequestedBy: decision.RemoteAddr,
		Timestamp:   decision.Timestamp,
	}

	if decision.Metrics != nil {
		event.Metrics = decision.Metrics.All()
	}

	if decision.Error != nil {
		event.Error = decision.Error
	}

	err := p.excludeEvent(ctx, decision.Txn, &event)
	if err != nil {
		// TODO(tsandall): see note below about error handling.
		p.logError("Log event exclusion failed: %v.", err)
		return nil
	}

	err = p.maskEvent(ctx, decision.Txn, &event)
	if err != nil {
		// TODO(tsandall): see note below about error handling.
		p.logError("Log event masking failed: %v.", err)
		return nil
	}

	err = p.minimizeEvent(ctx, decision.Txn, &event)
	if err != nil {
		// TODO(tsandall): see note below about error handling.
		p.logError("Log event minimization failed: %v.", err)
		return nil
	}

	err = p.tokenizeEvent(ctx, decision.Txn, &event)
	if err != nil {
		// TODO(tsandall): see note below about error handling.
		p.logError("Log event tokenization failed: %v.", err)
		return nil
	}

	if p.config.ConsoleLogs {
		err := p.logEvent(event)
		if err != nil {
			p.logError("Failed to log to console: %v.", err)
		}
	}

	if p.config.Plugin != nil {
		proxy, ok := p.manager.Plugin(*p.config.Plugin).(Logger)
		if !ok {
			return fmt.Errorf("plugin does not implement Logger interface")
		}
		return proxy.Log(ctx, event)
	}

	if p.config.Service != "" {
		p.mtx.Lock()
		defer p.mtx.Unlock()

		result, err := p.enc.Write(event)
		if err != nil {
			// TODO(tsandall): revisit this now that we have an API that
			// can return an error. Should the default behaviour be to
			// fail-closed as we do for plugins?
			p.logError("Log encoding failed: %v.", err)
			return nil
		}

		if result != nil {
			p.bufferChunk(p.buffer, result)
		}
	}

	return nil
}

// Reconfigure notifies the plugin with a new configuration.
func (p *Plugin) Reconfigure(_ context.Context, config interface{}) {

	done := make(chan struct{})
	p.reconfig <- reconfigure{config: config, done: done}

	p.maskMutex.Lock()
	defer p.maskMutex.Unlock()
	p.exclude = nil
	p.mask = nil
	p.minimize = nil
	p.tokenize = nil

	_ = <-done
}

// compilerUpdated is called when a compiler trigger on the plugin manager
// fires. This indicates a new compiler instance is available. The decision
// logger needs to prepare a new masking query.
func (p *Plugin) compilerUpdated(txn storage.Transaction) {
	p.maskMutex.Lock()
	defer p.maskMutex.Unlock()
	p.exclude = nil
	p.mask = nil
	p.minimize = nil
	p.tokenize = nil
}

func (p *Plugin) loop() {

	ctx, cancel := context.WithCancel(context.Background())

	var retry int

	for {
		var err error

		if p.config.Service != "" {
			var uploaded bool
			uploaded, err = p.oneShot(ctx)

			if err != nil {
				p.logError("%v.", err)
			} else if uploaded {
				p.logInfo("Logs uploaded successfully.")
			} else {
				p.logInfo("Log upload skipped.")
			}
		}

		var delay time.Duration

		if err == nil {
			min := float64(*p.config.Reporting.MinDelaySeconds)
			max := float64(*p.config.Reporting.MaxDelaySeconds)
			delay = time.Duration(((max - min) * rand.Float64()) + min)
		} else {
			delay = util.DefaultBackoff(float64(minRetryDelay), float64(*p.config.Reporting.MaxDelaySeconds), retry)
		}

		if p.config.Service != "" {
			p.logDebug("Waiting %v before next upload/retry.", delay)
		}

		timer := time.NewTimer(delay)

		select {
		case <-timer.C:
			if err != nil {
				retry++
			} else {
				retry = 0
			}
		case update := <-p.reconfig:
			p.reconfigure(update.config)
			update.done <- struct{}{}
		case done := <-p.stop:
			cancel()
			done <- struct{}{}
			return
		}
	}
}

func (p *Plugin) oneShot(ctx context.Context) (ok bool, err error) {
	// Make a local copy of the plugins's encoder and buffer and create
	// a new encoder and buffer. This is needed as locking the buffer for
	// the upload duration will block policy evaluation and result in
	// increased latency for OPA clients
	p.mtx.Lock()
	oldChunkEnc := p.enc
	oldBuffer := p.buffer
	p.buffer = newLogBuffer(*p.config.Reporting.BufferSizeLimitBytes)
	p.enc = newChunkEncoder(*p.config.Reporting.UploadSizeLimitBytes)
	p.mtx.Unlock()

	// Along with uploading the compressed events in the buffer
	// to the remote server, flush any pending compressed data to the
	// underlying writer and add to the buffer.
	chunk, err := oldChunkEnc.Flush()
	if err != nil {
		return false, err
	} else if chunk != nil {
		p.bufferChunk(oldBuffer, chunk)
	}

	if oldBuffer.Len() == 0 {
		return false, nil
	}

	for bs := oldBuffer.Pop(); bs != nil; bs = oldBuffer.Pop() {
		err := uploadChunk(ctx, p.manager.Client(p.config.Service), p.config.PartitionName, bs)
		if err != nil {
			// requeue the chunk
			p.mtx.Lock()
			p.bufferChunk(p.buffer, bs)
			p.mtx.Unlock()
			return false, err
		}
	}

	return true, nil
}

func (p *Plugin) reconfigure(config interface{}) {

	newConfig := config.(*Config)

	if reflect.DeepEqual(p.config, *newConfig) {
		p.logDebug("Decision log uploader configuration unchanged.")
		return
	}

	p.logInfo("Decision log uploader configuration changed.")
	p.config = *newConfig
}

func (p *Plugin) bufferChunk(buffer *logBuffer, bs []byte) {
	dropped := buffer.Push(bs)
	if dropped > 0 {
		p.logError("Dropped %v chunks from buffer. Reduce reporting interval or increase buffer size.", dropped)
	}
}

func (p *Plugin) excludeEvent(ctx context.Context, txn storage.Transaction, event *EventV1) error {

	err := func() error {

		p.maskMutex.Lock()
		defer p.maskMutex.Unlock()

		if p.exclude == nil {

			query := ast.NewBody(ast.NewExpr(ast.NewTerm(p.config.excludeDecisionRef)))

			r := rego.New(
				rego.ParsedQuery(query),
				rego.Compiler(p.manager.GetCompiler()),
				rego.Store(p.manager.Store),
				rego.Transaction(txn),
				rego.Runtime(p.manager.Info),
			)

			pq, err := r.PrepareForEval(context.Background())
			if err != nil {
				return err
			}

			p.exclude = &pq
		}

		return nil
	}()

	if err != nil {
		return err
	}

	rs, err := p.exclude.Eval(
		ctx,
		rego.EvalInput(event),
		rego.EvalTransaction(txn),
	)

	if err != nil {
		return err
	} else if len(rs) == 0 {
		return nil
	}

	ptrs, err := resultValueToPtrs(rs[0].Expressions[0].Value)
	if err != nil {
		return err
	}

	for _, ptr := range ptrs {
		ptr.Erase(event)
	}

	return nil
}


func (p *Plugin) maskEvent(ctx context.Context, txn storage.Transaction, event *EventV1) error {

	err := func() error {

		p.maskMutex.Lock()
		defer p.maskMutex.Unlock()

		if p.mask == nil {

			query := ast.NewBody(ast.NewExpr(ast.NewTerm(p.config.maskDecisionRef)))

			r := rego.New(
				rego.ParsedQuery(query),
				rego.Compiler(p.manager.GetCompiler()),
				rego.Store(p.manager.Store),
				rego.Transaction(txn),
				rego.Runtime(p.manager.Info),
			)

			pq, err := r.PrepareForEval(context.Background())
			if err != nil {
				return err
			}

			p.mask = &pq
		}

		return nil
	}()

	if err != nil {
		return err
	}

	rs, err := p.mask.Eval(
		ctx,
		rego.EvalInput(event),
		rego.EvalTransaction(txn),
	)

	if err != nil {
		return err
	} else if len(rs) == 0 {
		return nil
	}

	ptrs, err := resultValueToPtrs(rs[0].Expressions[0].Value)
	if err != nil {
		return err
	}

	for _, ptr := range ptrs {
		ptr.Mask(event)
	}

	return nil
}

func (p *Plugin) minimizeEvent(ctx context.Context, txn storage.Transaction, event *EventV1) error {

	err := func() error {

		p.maskMutex.Lock()
		defer p.maskMutex.Unlock()

		if p.minimize == nil {

			query := ast.NewBody(ast.NewExpr(ast.NewTerm(p.config.minimizeDecisionRef)))

			r := rego.New(
				rego.ParsedQuery(query),
				rego.Compiler(p.manager.GetCompiler()),
				rego.Store(p.manager.Store),
				rego.Transaction(txn),
				rego.Runtime(p.manager.Info),
			)

			pq, err := r.PrepareForEval(context.Background())
			if err != nil {
				return err
			}

			p.minimize = &pq
		}

		return nil
	}()

	if err != nil {
		return err
	}

	rs, err := p.minimize.Eval(
		ctx,
		rego.EvalInput(event),
		rego.EvalTransaction(txn),
	)

	if err != nil {
		return err
	} else if len(rs) == 0 {
		return nil
	}

	ptrs, err := resultValueToPtrs(rs[0].Expressions[0].Value)
	if err != nil {
		return err
	}

	for _, ptr := range ptrs {
		ptr.Minimize(p.config.MinimizationLevel, event)
	}

	return nil
}

func (p *Plugin) tokenizeEvent(ctx context.Context, txn storage.Transaction, event *EventV1) error {

	err := func() error {

		p.maskMutex.Lock()
		defer p.maskMutex.Unlock()

		if p.tokenize == nil {

			query := ast.NewBody(ast.NewExpr(ast.NewTerm(p.config.tokenizeDecisionRef)))

			r := rego.New(
				rego.ParsedQuery(query),
				rego.Compiler(p.manager.GetCompiler()),
				rego.Store(p.manager.Store),
				rego.Transaction(txn),
				rego.Runtime(p.manager.Info),
			)

			pq, err := r.PrepareForEval(context.Background())
			if err != nil {
				return err
			}

			p.tokenize = &pq
		}

		return nil
	}()

	if err != nil {
		return err
	}

	rs, err := p.tokenize.Eval(
		ctx,
		rego.EvalInput(event),
		rego.EvalTransaction(txn),
	)

	if err != nil {
		return err
	} else if len(rs) == 0 {
		return nil
	}

	ptrs, err := resultValueToPtrs(rs[0].Expressions[0].Value)
	if err != nil {
		return err
	}

	for _, ptr := range ptrs {
		ptr.Tokenize(event)
	}

	return nil
}

func uploadChunk(ctx context.Context, client rest.Client, partitionName string, data []byte) error {

	resp, err := client.
		WithHeader("Content-Type", "application/json").
		WithHeader("Content-Encoding", "gzip").
		WithBytes(data).
		Do(ctx, "POST", fmt.Sprintf("/logs/%v", partitionName))

	if err != nil {
		return errors.Wrap(err, "Log upload failed")
	}

	defer util.Close(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("Log upload failed, server replied with not found")
	case http.StatusUnauthorized:
		return fmt.Errorf("Log upload failed, server replied with not authorized")
	default:
		return fmt.Errorf("Log upload failed, server replied with HTTP %v", resp.StatusCode)
	}
}

func (p *Plugin) logError(fmt string, a ...interface{}) {
	logrus.WithFields(p.logrusFields()).Errorf(fmt, a...)
}

func (p *Plugin) logInfo(fmt string, a ...interface{}) {
	logrus.WithFields(p.logrusFields()).Infof(fmt, a...)
}

func (p *Plugin) logDebug(fmt string, a ...interface{}) {
	logrus.WithFields(p.logrusFields()).Debugf(fmt, a...)
}

func (p *Plugin) logrusFields() logrus.Fields {
	return logrus.Fields{
		"plugin": Name,
	}
}

func (p *Plugin) logEvent(event EventV1) error {
	eventBuf, err := json.Marshal(&event)
	if err != nil {
		return err
	}
	fields := logrus.Fields{}
	err = util.UnmarshalJSON(eventBuf, &fields)
	if err != nil {
		return err
	}
	logrus.WithFields(fields).WithFields(logrus.Fields{
		"type": "openpolicyagent.org/decision_logs",
	}).Info("Decision Log")
	return nil
}
