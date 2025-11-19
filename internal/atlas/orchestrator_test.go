package atlas

import (
	"context"
	"sync"
	"testing"
	"time"
)

// mockModule is a test module that returns configurable findings.
type mockModule struct {
	name        string
	description string
	findings    []*Finding
	delay       time.Duration
	err         error
}

func (m *mockModule) Name() string        { return m.name }
func (m *mockModule) Description() string { return m.description }

func (m *mockModule) Scan(ctx context.Context, target *ScanTarget) ([]*Finding, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.err != nil {
		return nil, m.err
	}
	return m.findings, nil
}

func (m *mockModule) SupportsTarget(target *ScanTarget) bool {
	return true
}

func TestOrchestratorStartScan(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	module := &mockModule{
		name:        "test-module",
		description: "Test module",
		findings: []*Finding{
			{
				Type:       "XSS",
				Severity:   SeverityHigh,
				Confidence: ConfidenceConfirmed,
				Title:      "Reflected XSS",
				URL:        "http://example.com/search",
				Parameter:  "q",
				Location:   ParamLocationQuery,
			},
		},
	}

	orchestrator := NewOrchestrator(
		[]Module{module},
		storage,
		nil, // OAST client
		eventBus,
		logger,
	)

	scan := &Scan{
		ID:   "test-scan-1",
		Name: "Test Scan",
		Target: Target{
			Type:    TargetTypeSingleURL,
			BaseURL: "http://example.com",
		},
		Config: DefaultScanConfig(),
	}

	ctx := context.Background()
	err := orchestrator.StartScan(ctx, scan)
	if err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}

	// Poll for scan completion
	var status *Scan
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status, err = orchestrator.GetScanStatus(scan.ID)
		if err == nil && status.State == ScanStateCompleted {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if status == nil {
		t.Fatal("failed to get scan status")
	}

	if status.State != ScanStateCompleted {
		t.Errorf("expected state %s, got %s", ScanStateCompleted, status.State)
	}

	// Check findings were collected
	if len(status.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(status.Findings))
	}
}

func TestOrchestratorStopScan(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	// Module with delay to allow stopping
	module := &mockModule{
		name:  "slow-module",
		delay: 1 * time.Second,
	}

	orchestrator := NewOrchestrator(
		[]Module{module},
		storage,
		nil,
		eventBus,
		logger,
	)

	scan := &Scan{
		ID:   "test-scan-2",
		Name: "Test Scan",
		Target: Target{
			Type:    TargetTypeSingleURL,
			BaseURL: "http://example.com",
		},
		Config: DefaultScanConfig(),
	}

	ctx := context.Background()
	err := orchestrator.StartScan(ctx, scan)
	if err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}

	// Stop immediately
	err = orchestrator.StopScan(scan.ID)
	if err != nil {
		t.Fatalf("StopScan failed: %v", err)
	}

	// Verify scan was removed
	_, err = orchestrator.GetScanStatus(scan.ID)
	if err == nil {
		t.Error("expected error getting stopped scan status")
	}
}

func TestOrchestratorDuplicateScan(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	module := &mockModule{
		name:  "test-module",
		delay: 100 * time.Millisecond,
	}

	orchestrator := NewOrchestrator(
		[]Module{module},
		storage,
		nil,
		eventBus,
		logger,
	)

	scan := &Scan{
		ID:   "test-scan-3",
		Name: "Test Scan",
		Target: Target{
			Type:    TargetTypeSingleURL,
			BaseURL: "http://example.com",
		},
		Config: DefaultScanConfig(),
	}

	ctx := context.Background()
	err := orchestrator.StartScan(ctx, scan)
	if err != nil {
		t.Fatalf("first StartScan failed: %v", err)
	}

	// Try to start same scan again
	err = orchestrator.StartScan(ctx, scan)
	if err == nil {
		t.Error("expected error starting duplicate scan")
	}
}

func TestOrchestratorModuleSelection(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	module1 := &mockModule{name: "module-1"}
	module2 := &mockModule{name: "module-2"}
	module3 := &mockModule{name: "module-3"}

	orchestrator := NewOrchestrator(
		[]Module{module1, module2, module3},
		storage,
		nil,
		eventBus,
		logger,
	)

	t.Run("EnabledModules", func(t *testing.T) {
		config := DefaultScanConfig()
		config.EnabledModules = []string{"module-1", "module-3"}

		enabled := orchestrator.getEnabledModules(config)
		if len(enabled) != 2 {
			t.Errorf("expected 2 enabled modules, got %d", len(enabled))
		}
	})

	t.Run("DisabledModules", func(t *testing.T) {
		config := DefaultScanConfig()
		config.DisabledModules = []string{"module-2"}

		enabled := orchestrator.getEnabledModules(config)
		if len(enabled) != 2 {
			t.Errorf("expected 2 enabled modules, got %d", len(enabled))
		}
	})
}

func TestOrchestratorListActiveScans(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	module := &mockModule{
		name:  "test-module",
		delay: 200 * time.Millisecond,
	}

	orchestrator := NewOrchestrator(
		[]Module{module},
		storage,
		nil,
		eventBus,
		logger,
	)

	// Start multiple scans
	for i := 0; i < 3; i++ {
		scan := &Scan{
			ID:   "scan-" + string(rune('a'+i)),
			Name: "Test Scan",
			Target: Target{
				Type:    TargetTypeSingleURL,
				BaseURL: "http://example.com",
			},
			Config: DefaultScanConfig(),
		}
		err := orchestrator.StartScan(context.Background(), scan)
		if err != nil {
			t.Fatalf("StartScan %d failed: %v", i, err)
		}
	}

	// Check active scans
	active := orchestrator.ListActiveScans()
	if len(active) != 3 {
		t.Errorf("expected 3 active scans, got %d", len(active))
	}
}

func TestOrchestratorEventEmission(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	module := &mockModule{
		name: "test-module",
		findings: []*Finding{
			{Type: "XSS", Severity: SeverityHigh},
		},
	}

	orchestrator := NewOrchestrator(
		[]Module{module},
		storage,
		nil,
		eventBus,
		logger,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Subscribe to events
	events := eventBus.Subscribe(ctx, "*")

	var received []Event
	var mu sync.Mutex
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			select {
			case event, ok := <-events:
				if !ok {
					return
				}
				mu.Lock()
				received = append(received, event)
				mu.Unlock()
			case <-time.After(500 * time.Millisecond):
				return
			}
		}
	}()

	scan := &Scan{
		ID:   "test-scan-events",
		Name: "Test Scan",
		Target: Target{
			Type:    TargetTypeSingleURL,
			BaseURL: "http://example.com",
		},
		Config: DefaultScanConfig(),
	}

	err := orchestrator.StartScan(context.Background(), scan)
	if err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}

	<-done

	mu.Lock()
	defer mu.Unlock()

	// Should have received: started, progress updates, finding discovered, completed
	if len(received) < 3 {
		t.Errorf("expected at least 3 events, got %d", len(received))
	}
}

func TestOrchestratorValidation(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	orchestrator := NewOrchestrator(
		[]Module{},
		storage,
		nil,
		eventBus,
		logger,
	)

	t.Run("MissingID", func(t *testing.T) {
		scan := &Scan{
			Name: "Test Scan",
			Target: Target{
				Type:    TargetTypeSingleURL,
				BaseURL: "http://example.com",
			},
		}
		err := orchestrator.StartScan(context.Background(), scan)
		if err == nil {
			t.Error("expected error for missing ID")
		}
	})

	t.Run("MissingTarget", func(t *testing.T) {
		scan := &Scan{
			ID:   "test-scan",
			Name: "Test Scan",
		}
		err := orchestrator.StartScan(context.Background(), scan)
		if err == nil {
			t.Error("expected error for missing target")
		}
	})
}
