package atlas

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Logger defines the logging interface for the orchestrator.
type Logger interface {
	Debug(msg string, keyvals ...interface{})
	Info(msg string, keyvals ...interface{})
	Warn(msg string, keyvals ...interface{})
	Error(msg string, keyvals ...interface{})
}

// Orchestrator coordinates vulnerability scans across multiple modules.
type Orchestrator struct {
	modules    []Module
	storage    Storage
	oastClient OASTClient
	eventBus   EventBus
	logger     Logger

	// Active scans
	scans map[string]*scanRunner
	mu    sync.RWMutex
}

// scanRunner manages the execution of a single scan.
type scanRunner struct {
	scan     *Scan
	ctx      context.Context
	cancel   context.CancelFunc
	modules  []Module
	findings chan *Finding
	wg       sync.WaitGroup

	// State management
	stateMu  sync.RWMutex
	state    ScanState
	progress Progress
}

// NewOrchestrator creates a new scan orchestrator.
func NewOrchestrator(
	modules []Module,
	storage Storage,
	oastClient OASTClient,
	eventBus EventBus,
	logger Logger,
) *Orchestrator {
	return &Orchestrator{
		modules:    modules,
		storage:    storage,
		oastClient: oastClient,
		eventBus:   eventBus,
		logger:     logger,
		scans:      make(map[string]*scanRunner),
	}
}

// StartScan initiates a new scan.
func (o *Orchestrator) StartScan(ctx context.Context, scan *Scan) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Validate scan config
	if err := o.validateScan(scan); err != nil {
		return fmt.Errorf("invalid scan config: %w", err)
	}

	// Check if already running
	if _, exists := o.scans[scan.ID]; exists {
		return fmt.Errorf("scan %s already running", scan.ID)
	}

	// Create scan context
	scanCtx, cancel := context.WithCancel(ctx)

	runner := &scanRunner{
		scan:     scan,
		ctx:      scanCtx,
		cancel:   cancel,
		modules:  o.getEnabledModules(scan.Config),
		findings: make(chan *Finding, 100), // Buffered channel
		state:    ScanStateRunning,
	}

	o.scans[scan.ID] = runner

	// Start scan in background
	go o.runScan(runner)

	o.logger.Info("scan started",
		"scan_id", scan.ID,
		"target", scan.Target.BaseURL,
		"modules", len(runner.modules),
	)

	return nil
}

func (o *Orchestrator) runScan(runner *scanRunner) {
	defer func() {
		runner.cancel()
		o.mu.Lock()
		delete(o.scans, runner.scan.ID)
		o.mu.Unlock()
	}()

	scan := runner.scan
	scan.StartTime = time.Now()
	scan.State = ScanStateRunning

	// Emit scan started event
	o.eventBus.Publish("atlas.scan.started", scan)

	// Phase 1: Discovery
	o.updateProgress(runner, "discovery", 0)
	targets, err := o.discover(runner)
	if err != nil {
		o.failScan(runner, err)
		return
	}

	o.logger.Info("discovery complete",
		"scan_id", scan.ID,
		"targets_found", len(targets),
	)

	// Phase 2: Analysis
	o.updateProgress(runner, "analysis", 0.3)

	// Start finding collector (separate from module WaitGroup)
	collectorDone := make(chan struct{})
	go func() {
		o.collectFindings(runner)
		close(collectorDone)
	}()

	// Run modules in parallel
	for _, module := range runner.modules {
		runner.wg.Add(1)
		go o.runModule(runner, module, targets)
	}

	// Wait for all modules to complete
	runner.wg.Wait()
	close(runner.findings)

	// Wait for collector to finish processing
	<-collectorDone

	// Phase 3: Finalization
	now := time.Now()
	scan.EndTime = &now
	scan.Duration = time.Since(scan.StartTime)
	scan.State = ScanStateCompleted

	// Update runner state
	runner.stateMu.Lock()
	runner.state = ScanStateCompleted
	runner.stateMu.Unlock()

	o.updateProgress(runner, "completed", 1.0)

	// Persist final scan state
	if err := o.storage.StoreScan(runner.ctx, scan); err != nil {
		o.logger.Error("failed to persist scan",
			"scan_id", scan.ID,
			"error", err,
		)
	}

	// Emit scan completed event
	o.eventBus.Publish("atlas.scan.completed", scan)

	o.logger.Info("scan completed",
		"scan_id", scan.ID,
		"duration", scan.Duration,
		"findings", len(scan.Findings),
	)
}

func (o *Orchestrator) discover(runner *scanRunner) ([]*ScanTarget, error) {
	scan := runner.scan

	var targets []*ScanTarget

	switch scan.Target.Type {
	case TargetTypeSingleURL:
		targets = append(targets, &ScanTarget{
			URL:    scan.Target.BaseURL,
			Method: "GET",
		})

	case TargetTypeURLList:
		for _, url := range scan.Target.URLs {
			targets = append(targets, &ScanTarget{
				URL:    url,
				Method: "GET",
			})
		}

	case TargetTypeScope:
		// TODO: Use crawler to discover URLs
		// For now, convert start URLs to targets
		if scan.Target.Scope != nil {
			for _, url := range scan.Target.Scope.StartURLs {
				targets = append(targets, &ScanTarget{
					URL:    url,
					Method: "GET",
				})
			}
		}
	}

	// Update progress
	runner.stateMu.Lock()
	runner.progress.URLsDiscovered = len(targets)
	runner.progress.URLsRemaining = len(targets)
	runner.stateMu.Unlock()

	return targets, nil
}

func (o *Orchestrator) runModule(runner *scanRunner, module Module, targets []*ScanTarget) {
	defer runner.wg.Done()

	o.logger.Debug("module started",
		"scan_id", runner.scan.ID,
		"module", module.Name(),
	)

	for _, target := range targets {
		// Check if scan cancelled
		select {
		case <-runner.ctx.Done():
			return
		default:
		}

		// Check if module supports target
		if !module.SupportsTarget(target) {
			continue
		}

		// Update current module
		runner.stateMu.Lock()
		runner.progress.CurrentModule = module.Name()
		runner.stateMu.Unlock()

		// Run module scan
		findings, err := module.Scan(runner.ctx, target)
		if err != nil {
			o.logger.Warn("module scan failed",
				"module", module.Name(),
				"target", target.URL,
				"error", err,
			)
			continue
		}

		// Send findings to collector
		for _, finding := range findings {
			finding.ScanID = runner.scan.ID
			finding.DetectedBy = module.Name()
			finding.DetectedAt = time.Now()

			select {
			case runner.findings <- finding:
			case <-runner.ctx.Done():
				return
			}
		}

		// Update progress
		runner.stateMu.Lock()
		runner.progress.URLsTested++
		runner.progress.URLsRemaining--
		runner.progress.RequestsSent++
		runner.stateMu.Unlock()
	}

	o.logger.Debug("module completed",
		"scan_id", runner.scan.ID,
		"module", module.Name(),
	)
}

func (o *Orchestrator) collectFindings(runner *scanRunner) {
	seen := make(map[string]bool) // For deduplication

	for finding := range runner.findings {
		// Deduplicate
		key := o.findingKey(finding)
		if seen[key] {
			continue
		}
		seen[key] = true

		// Store finding
		if err := o.storage.StoreFinding(runner.ctx, finding); err != nil {
			o.logger.Error("failed to store finding", "error", err)
			continue
		}

		// Add to scan
		runner.scan.Findings = append(runner.scan.Findings, finding)

		// Update progress
		runner.stateMu.Lock()
		runner.progress.FindingsFound++
		runner.stateMu.Unlock()

		// Emit finding event
		o.eventBus.Publish("atlas.finding.discovered", finding)

		o.logger.Info("finding discovered",
			"scan_id", runner.scan.ID,
			"type", finding.Type,
			"severity", finding.Severity,
			"url", finding.URL,
		)
	}
}

func (o *Orchestrator) findingKey(f *Finding) string {
	return fmt.Sprintf("%s:%s:%s:%s", f.Type, f.URL, f.Parameter, f.Location)
}

func (o *Orchestrator) updateProgress(runner *scanRunner, phase string, pct float64) {
	runner.stateMu.Lock()
	defer runner.stateMu.Unlock()

	runner.progress.Phase = phase
	runner.progress.PercentComplete = pct

	// Estimate time remaining
	elapsed := time.Since(runner.scan.StartTime)
	if pct > 0 {
		total := time.Duration(float64(elapsed) / pct)
		runner.progress.EstimatedTimeRemaining = total - elapsed
	}

	// Emit progress event
	o.eventBus.Publish("atlas.scan.progress", runner.progress)
}

func (o *Orchestrator) failScan(runner *scanRunner, err error) {
	runner.scan.State = ScanStateFailed
	now := time.Now()
	runner.scan.EndTime = &now

	o.eventBus.Publish("atlas.scan.failed", map[string]interface{}{
		"scan_id": runner.scan.ID,
		"error":   err.Error(),
	})

	o.logger.Error("scan failed",
		"scan_id", runner.scan.ID,
		"error", err,
	)
}

// PauseScan pauses a running scan.
func (o *Orchestrator) PauseScan(scanID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	runner, exists := o.scans[scanID]
	if !exists {
		return fmt.Errorf("scan %s not found", scanID)
	}

	runner.stateMu.Lock()
	defer runner.stateMu.Unlock()

	if runner.state != ScanStateRunning {
		return fmt.Errorf("scan %s is not running", scanID)
	}

	runner.state = ScanStatePaused
	runner.cancel() // Stop modules

	o.logger.Info("scan paused", "scan_id", scanID)
	return nil
}

// ResumeScan resumes a paused scan.
func (o *Orchestrator) ResumeScan(ctx context.Context, scanID string) error {
	// Get scan from storage
	scan, err := o.storage.GetScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("failed to get scan: %w", err)
	}

	if scan.State != ScanStatePaused {
		return fmt.Errorf("scan %s is not paused", scanID)
	}

	// Reset state and restart
	scan.State = ScanStatePending
	return o.StartScan(ctx, scan)
}

// StopScan stops a running scan.
func (o *Orchestrator) StopScan(scanID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	runner, exists := o.scans[scanID]
	if !exists {
		return fmt.Errorf("scan %s not found", scanID)
	}

	runner.cancel()
	runner.scan.State = ScanStateCancelled

	delete(o.scans, scanID)

	o.logger.Info("scan stopped", "scan_id", scanID)
	return nil
}

// GetScanStatus returns current scan status.
func (o *Orchestrator) GetScanStatus(scanID string) (*Scan, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	runner, exists := o.scans[scanID]
	if !exists {
		// Check storage for completed scans
		return o.storage.GetScan(context.Background(), scanID)
	}

	runner.stateMu.RLock()
	defer runner.stateMu.RUnlock()

	// Return copy
	scan := *runner.scan
	scan.Progress = runner.progress
	scan.State = runner.state

	return &scan, nil
}

// ListActiveScans returns all currently running scans.
func (o *Orchestrator) ListActiveScans() []*Scan {
	o.mu.RLock()
	defer o.mu.RUnlock()

	scans := make([]*Scan, 0, len(o.scans))
	for _, runner := range o.scans {
		runner.stateMu.RLock()
		scan := *runner.scan
		scan.Progress = runner.progress
		scan.State = runner.state
		runner.stateMu.RUnlock()
		scans = append(scans, &scan)
	}

	return scans
}

func (o *Orchestrator) validateScan(scan *Scan) error {
	if scan.ID == "" {
		return fmt.Errorf("scan ID required")
	}
	if scan.Target.BaseURL == "" && len(scan.Target.URLs) == 0 {
		return fmt.Errorf("target required")
	}
	return nil
}

func (o *Orchestrator) getEnabledModules(config ScanConfig) []Module {
	// If specific modules enabled, use only those
	if len(config.EnabledModules) > 0 {
		var enabled []Module
		for _, m := range o.modules {
			for _, name := range config.EnabledModules {
				if m.Name() == name {
					enabled = append(enabled, m)
					break
				}
			}
		}
		return enabled
	}

	// Otherwise, use all except disabled
	var enabled []Module
	disabled := make(map[string]bool)
	for _, name := range config.DisabledModules {
		disabled[name] = true
	}

	for _, m := range o.modules {
		if !disabled[m.Name()] {
			enabled = append(enabled, m)
		}
	}

	return enabled
}

// RegisterModule adds a new module to the orchestrator.
func (o *Orchestrator) RegisterModule(module Module) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.modules = append(o.modules, module)
}

// GetModules returns all registered modules.
func (o *Orchestrator) GetModules() []Module {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return append([]Module(nil), o.modules...)
}
