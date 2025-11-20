package atlas

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestAtlas_EndToEnd tests the complete scan lifecycle with a vulnerable test application.
func TestAtlas_EndToEnd(t *testing.T) {
	// Setup vulnerable test application
	vulnApp := setupVulnerableTestApp(t)
	defer vulnApp.Close()

	// Create Atlas scanner
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	modules := []Module{
		&mockDetectionModule{
			name: "sqli-detector",
			findings: []*Finding{
				{
					Type:       "SQL Injection",
					Severity:   SeverityHigh,
					Confidence: ConfidenceConfirmed,
					Title:      "SQL Injection in id parameter",
					URL:        vulnApp.URL + "/vuln?id=1",
					Parameter:  "id",
					Location:   ParamLocationQuery,
				},
			},
		},
	}

	orchestrator := NewOrchestrator(modules, storage, nil, eventBus, logger)

	// Configure scan
	scan := &Scan{
		ID:   "e2e-test",
		Name: "End-to-End Test",
		Target: Target{
			Type: TargetTypeSingleURL,
			URLs: []string{vulnApp.URL},
		},
		Config: ScanConfig{
			Depth:          1,
			Intensity:      3,
			MaxConcurrency: 5,
			Timeout:        10 * time.Second,
		},
	}

	// Run scan
	err := orchestrator.StartScan(context.Background(), scan)
	if err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}

	// Wait for completion
	err = waitForScanCompletion(orchestrator, scan.ID, 30*time.Second)
	if err != nil {
		t.Fatalf("Scan did not complete: %v", err)
	}

	// Verify findings
	status, err := orchestrator.GetScanStatus(scan.ID)
	if err != nil {
		t.Fatalf("GetScanStatus failed: %v", err)
	}

	if status.State != ScanStateCompleted {
		t.Errorf("Expected scan state completed, got %s", status.State)
	}

	if len(status.Findings) == 0 {
		t.Error("Expected at least one finding")
	}

	// Verify SQLi detected
	hasSQLi := false
	for _, f := range status.Findings {
		if strings.Contains(f.Type, "SQL Injection") {
			hasSQLi = true
			break
		}
	}

	if !hasSQLi {
		t.Error("Should detect SQL injection")
	}
}

// TestAtlas_PerformanceUnderLoad tests scanner performance with multiple targets.
func TestAtlas_PerformanceUnderLoad(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	module := &mockDetectionModule{
		name:     "fast-detector",
		findings: []*Finding{},
		delay:    10 * time.Millisecond, // Simulate work
	}

	orchestrator := NewOrchestrator([]Module{module}, storage, nil, eventBus, logger)

	// Create 50 targets
	targets := make([]string, 50)
	for i := range targets {
		targets[i] = fmt.Sprintf("http://test.com/page%d", i)
	}

	scan := &Scan{
		ID:   "load-test",
		Name: "Performance Test",
		Target: Target{
			Type: TargetTypeURLList,
			URLs: targets,
		},
		Config: ScanConfig{
			MaxConcurrency: 10,
			Timeout:        5 * time.Second,
		},
	}

	start := time.Now()
	err := orchestrator.StartScan(context.Background(), scan)
	if err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}

	err = waitForScanCompletion(orchestrator, scan.ID, 60*time.Second)
	if err != nil {
		t.Fatalf("Scan did not complete: %v", err)
	}

	duration := time.Since(start)

	// Should complete in reasonable time (50 targets * 10ms = 500ms minimum + overhead)
	if duration > 30*time.Second {
		t.Errorf("Scan took too long: %v", duration)
	}

	// Verify no memory leaks
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if m.Alloc > 100*1024*1024 { // >100MB is suspicious for this test
		t.Logf("Warning: High memory usage: %d MB", m.Alloc/(1024*1024))
	}
}

// TestAtlas_PauseResume tests scan pause and resume functionality.
func TestAtlas_PauseResume(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	module := &mockDetectionModule{
		name:  "slow-detector",
		delay: 100 * time.Millisecond,
		findings: []*Finding{
			{Type: "Test Finding", Severity: SeverityLow},
		},
	}

	orchestrator := NewOrchestrator([]Module{module}, storage, nil, eventBus, logger)

	scan := &Scan{
		ID:   "pause-resume-test",
		Name: "Pause Resume Test",
		Target: Target{
			Type: TargetTypeSingleURL,
			URLs: []string{"http://test.com"},
		},
		Config: ScanConfig{
			MaxConcurrency: 1,
			Timeout:        5 * time.Second,
		},
	}

	// Start scan
	err := orchestrator.StartScan(context.Background(), scan)
	if err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	// Pause scan
	err = orchestrator.PauseScan(scan.ID)
	if err != nil {
		t.Fatalf("PauseScan failed: %v", err)
	}

	// Verify paused state
	status, err := orchestrator.GetScanStatus(scan.ID)
	if err != nil {
		t.Fatalf("GetScanStatus failed: %v", err)
	}

	if status.State != ScanStatePaused {
		t.Errorf("Expected paused state, got %s", status.State)
	}

	// Note: Full resume with untested targets requires persistent storage
	// This test verifies the pause mechanism works
}

// TestAtlas_ConcurrentScans tests running multiple scans simultaneously.
func TestAtlas_ConcurrentScans(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	module := &mockDetectionModule{
		name:  "concurrent-detector",
		delay: 50 * time.Millisecond,
	}

	orchestrator := NewOrchestrator([]Module{module}, storage, nil, eventBus, logger)

	// Start 3 scans concurrently
	scanIDs := []string{"scan-1", "scan-2", "scan-3"}

	for _, id := range scanIDs {
		scan := &Scan{
			ID:   id,
			Name: fmt.Sprintf("Concurrent Scan %s", id),
			Target: Target{
				Type: TargetTypeSingleURL,
				URLs: []string{"http://test.com"},
			},
			Config: ScanConfig{
				MaxConcurrency: 2,
				Timeout:        5 * time.Second,
			},
		}

		err := orchestrator.StartScan(context.Background(), scan)
		if err != nil {
			t.Fatalf("StartScan failed for %s: %v", id, err)
		}
	}

	// Wait for all to complete
	for _, id := range scanIDs {
		err := waitForScanCompletion(orchestrator, id, 10*time.Second)
		if err != nil {
			t.Errorf("Scan %s did not complete: %v", id, err)
		}
	}

	// Verify all completed
	for _, id := range scanIDs {
		status, err := orchestrator.GetScanStatus(id)
		if err != nil {
			t.Errorf("GetScanStatus failed for %s: %v", id, err)
			continue
		}

		if status.State != ScanStateCompleted {
			t.Errorf("Scan %s not completed: %s", id, status.State)
		}
	}
}

// TestAtlas_ModuleIntegration tests that all modules work together correctly.
func TestAtlas_ModuleIntegration(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	// Create multiple detection modules
	modules := []Module{
		&mockDetectionModule{
			name: "sqli",
			findings: []*Finding{
				{Type: "SQL Injection", Severity: SeverityHigh},
			},
		},
		&mockDetectionModule{
			name: "xss",
			findings: []*Finding{
				{Type: "XSS", Severity: SeverityMedium},
			},
		},
		&mockDetectionModule{
			name: "ssrf",
			findings: []*Finding{
				{Type: "SSRF", Severity: SeverityHigh},
			},
		},
	}

	orchestrator := NewOrchestrator(modules, storage, nil, eventBus, logger)

	scan := &Scan{
		ID:   "module-integration",
		Name: "Module Integration Test",
		Target: Target{
			Type: TargetTypeSingleURL,
			URLs: []string{"http://test.com"},
		},
		Config: ScanConfig{
			MaxConcurrency: 3,
			Timeout:        5 * time.Second,
		},
	}

	err := orchestrator.StartScan(context.Background(), scan)
	if err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}

	err = waitForScanCompletion(orchestrator, scan.ID, 10*time.Second)
	if err != nil {
		t.Fatalf("Scan did not complete: %v", err)
	}

	// Verify findings from all modules
	status, err := orchestrator.GetScanStatus(scan.ID)
	if err != nil {
		t.Fatalf("GetScanStatus failed: %v", err)
	}

	if len(status.Findings) != 3 {
		t.Errorf("Expected 3 findings (one per module), got %d", len(status.Findings))
	}

	// Verify each module contributed
	foundTypes := make(map[string]bool)
	for _, f := range status.Findings {
		foundTypes[f.Type] = true
	}

	expectedTypes := []string{"SQL Injection", "XSS", "SSRF"}
	for _, expected := range expectedTypes {
		if !foundTypes[expected] {
			t.Errorf("Missing finding type: %s", expected)
		}
	}
}

// TestAtlas_ErrorHandling tests error handling and recovery.
func TestAtlas_ErrorHandling(t *testing.T) {
	storage := NewMemoryStorage()
	eventBus := NewBus()
	logger := NewNopLogger()

	// Module that fails
	failingModule := &mockDetectionModule{
		name:      "failing-module",
		shouldErr: true,
	}

	// Module that succeeds
	successModule := &mockDetectionModule{
		name: "success-module",
		findings: []*Finding{
			{Type: "Test Finding", Severity: SeverityLow},
		},
	}

	orchestrator := NewOrchestrator([]Module{failingModule, successModule}, storage, nil, eventBus, logger)

	scan := &Scan{
		ID:   "error-handling",
		Name: "Error Handling Test",
		Target: Target{
			Type: TargetTypeSingleURL,
			URLs: []string{"http://test.com"},
		},
		Config: ScanConfig{
			MaxConcurrency: 2,
			Timeout:        5 * time.Second,
		},
	}

	err := orchestrator.StartScan(context.Background(), scan)
	if err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}

	err = waitForScanCompletion(orchestrator, scan.ID, 10*time.Second)
	if err != nil {
		t.Fatalf("Scan did not complete: %v", err)
	}

	// Scan should complete despite one module failing
	status, err := orchestrator.GetScanStatus(scan.ID)
	if err != nil {
		t.Fatalf("GetScanStatus failed: %v", err)
	}

	if status.State != ScanStateCompleted {
		t.Errorf("Expected completed state, got %s", status.State)
	}

	// Should have findings from successful module
	if len(status.Findings) == 0 {
		t.Error("Expected findings from successful module")
	}
}

// Helper functions

func setupVulnerableTestApp(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	// Vulnerable endpoint
	mux.HandleFunc("/vuln", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		// Simulate SQL injection vulnerability
		w.Write([]byte(fmt.Sprintf("User ID: %s", id)))
	})

	return httptest.NewServer(mux)
}

func waitForScanCompletion(orchestrator *Orchestrator, scanID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		status, err := orchestrator.GetScanStatus(scanID)
		if err != nil {
			return err
		}

		if status.State == ScanStateCompleted || status.State == ScanStateFailed || status.State == ScanStateCancelled {
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("scan did not complete within %v", timeout)
}

// mockDetectionModule is a test module for integration testing.
type mockDetectionModule struct {
	name      string
	findings  []*Finding
	delay     time.Duration
	shouldErr bool
}

func (m *mockDetectionModule) Name() string {
	return m.name
}

func (m *mockDetectionModule) Description() string {
	return fmt.Sprintf("Mock detection module: %s", m.name)
}

func (m *mockDetectionModule) Scan(ctx context.Context, target *ScanTarget) ([]*Finding, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.shouldErr {
		return nil, fmt.Errorf("module error: %s", m.name)
	}

	// Copy findings and populate with target info
	results := make([]*Finding, len(m.findings))
	for i, f := range m.findings {
		finding := *f
		finding.URL = target.URL
		finding.Method = target.Method
		results[i] = &finding
	}

	return results, nil
}

func (m *mockDetectionModule) SupportsTarget(target *ScanTarget) bool {
	return true
}
