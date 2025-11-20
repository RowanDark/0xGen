package storage

import (
	"context"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/atlas"
)

func setupTestStorage(t *testing.T) *Storage {
	// Create temp database
	dbPath := t.TempDir() + "/test.db"

	logger := &testLogger{}
	storage, err := New(dbPath, logger)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	return storage
}

func TestStorage_ScanPersistence(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	scan := &atlas.Scan{
		ID:    "test-scan-1",
		Name:  "Test Scan",
		State: atlas.ScanStateRunning,
		Target: atlas.Target{
			Type: atlas.TargetTypeSingleURL,
			URLs: []string{"http://test.com"},
		},
		Config: atlas.ScanConfig{
			Timeout: 30 * time.Second,
		},
	}

	// Create scan
	err := storage.CreateScan(context.Background(), scan)
	if err != nil {
		t.Fatalf("CreateScan failed: %v", err)
	}

	// Retrieve scan
	loaded, err := storage.GetScan(context.Background(), scan.ID)
	if err != nil {
		t.Fatalf("GetScan failed: %v", err)
	}

	if loaded.ID != scan.ID {
		t.Errorf("Expected ID %s, got %s", scan.ID, loaded.ID)
	}

	if loaded.Name != scan.Name {
		t.Errorf("Expected name %s, got %s", scan.Name, loaded.Name)
	}

	if loaded.State != scan.State {
		t.Errorf("Expected state %s, got %s", scan.State, loaded.State)
	}
}

func TestStorage_UpdateScan(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	scan := &atlas.Scan{
		ID:    "test-scan-2",
		Name:  "Test Scan 2",
		State: atlas.ScanStatePending,
		Target: atlas.Target{
			Type: atlas.TargetTypeSingleURL,
			URLs: []string{"http://test.com"},
		},
		Config: atlas.ScanConfig{},
	}

	// Create scan
	storage.CreateScan(context.Background(), scan)

	// Update scan
	scan.State = atlas.ScanStateRunning
	scan.Progress.URLsTested = 10
	scan.Progress.PercentComplete = 0.5

	err := storage.UpdateScan(context.Background(), scan)
	if err != nil {
		t.Fatalf("UpdateScan failed: %v", err)
	}

	// Retrieve and verify
	loaded, err := storage.GetScan(context.Background(), scan.ID)
	if err != nil {
		t.Fatalf("GetScan failed: %v", err)
	}

	if loaded.State != atlas.ScanStateRunning {
		t.Errorf("Expected state running, got %s", loaded.State)
	}

	if loaded.Progress.URLsTested != 10 {
		t.Errorf("Expected 10 URLs tested, got %d", loaded.Progress.URLsTested)
	}

	if loaded.Progress.PercentComplete != 0.5 {
		t.Errorf("Expected 0.5 percent complete, got %f", loaded.Progress.PercentComplete)
	}
}

func TestStorage_FindingPersistence(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create scan first
	scan := &atlas.Scan{
		ID:     "test-scan-3",
		Name:   "Test Scan 3",
		State:  atlas.ScanStatePending,
		Target: atlas.Target{Type: atlas.TargetTypeSingleURL},
		Config: atlas.ScanConfig{},
	}
	storage.CreateScan(context.Background(), scan)

	// Create finding
	finding := &atlas.Finding{
		ID:          "finding-1",
		ScanID:      scan.ID,
		Type:        "XSS",
		Severity:    atlas.SeverityHigh,
		Confidence:  atlas.ConfidenceConfirmed,
		Title:       "Cross-Site Scripting",
		Description: "Found XSS vulnerability",
		URL:         "http://test.com/page",
		Method:      "GET",
		Parameter:   "q",
		Location:    atlas.ParamLocationQuery,
		CWE:         "CWE-79",
		OWASP:       "A03:2021",
		CVSS:        7.5,
		DetectedBy:  "xss-module",
		DetectedAt:  time.Now(),
	}

	err := storage.StoreFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("StoreFinding failed: %v", err)
	}

	// Retrieve findings by scan
	findings, err := storage.GetFindingsByScan(context.Background(), scan.ID)
	if err != nil {
		t.Fatalf("GetFindingsByScan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Type != "XSS" {
		t.Errorf("Expected type XSS, got %s", f.Type)
	}

	if f.Severity != atlas.SeverityHigh {
		t.Errorf("Expected high severity, got %s", f.Severity)
	}
}

func TestStorage_ScanTargetsPersistence(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	scanID := "test-scan-4"

	// Create scan
	scan := &atlas.Scan{
		ID:     scanID,
		Name:   "Test Scan 4",
		State:  atlas.ScanStatePending,
		Target: atlas.Target{Type: atlas.TargetTypeSingleURL},
		Config: atlas.ScanConfig{},
	}
	storage.CreateScan(context.Background(), scan)

	// Store targets
	targets := []*atlas.ScanTarget{
		{
			URL:    "http://test.com/page1",
			Method: "GET",
		},
		{
			URL:    "http://test.com/page2",
			Method: "POST",
		},
	}

	err := storage.StoreScanTargets(context.Background(), scanID, targets)
	if err != nil {
		t.Fatalf("StoreScanTargets failed: %v", err)
	}

	// Retrieve untested targets
	untested, err := storage.GetUntestedTargets(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetUntestedTargets failed: %v", err)
	}

	if len(untested) != 2 {
		t.Fatalf("Expected 2 untested targets, got %d", len(untested))
	}

	// Mark one as tested
	err = storage.MarkTargetTested(context.Background(), scanID, targets[0].URL)
	if err != nil {
		t.Fatalf("MarkTargetTested failed: %v", err)
	}

	// Verify only 1 untested remains
	untested, err = storage.GetUntestedTargets(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetUntestedTargets failed: %v", err)
	}

	if len(untested) != 1 {
		t.Fatalf("Expected 1 untested target, got %d", len(untested))
	}
}

func TestStorage_Checkpoints(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	scanID := "test-scan-5"

	// Create scan
	scan := &atlas.Scan{
		ID:     scanID,
		Name:   "Test Scan 5",
		State:  atlas.ScanStatePending,
		Target: atlas.Target{Type: atlas.TargetTypeSingleURL},
		Config: atlas.ScanConfig{},
	}
	storage.CreateScan(context.Background(), scan)

	// Create targets first (checkpoints have FK to targets)
	targets := []*atlas.ScanTarget{
		{URL: "http://test.com/page1", Method: "GET"},
		{URL: "http://test.com/page2", Method: "GET"},
		{URL: "http://test.com/page3", Method: "GET"},
	}
	err := storage.StoreScanTargets(context.Background(), scanID, targets)
	if err != nil {
		t.Fatalf("StoreScanTargets failed: %v", err)
	}

	// Create checkpoints (target_id corresponds to row id in scan_targets)
	err = storage.CreateCheckpoint(context.Background(), scanID, "sqli-module", 1)
	if err != nil {
		t.Fatalf("CreateCheckpoint failed: %v", err)
	}

	err = storage.CreateCheckpoint(context.Background(), scanID, "sqli-module", 2)
	if err != nil {
		t.Fatalf("CreateCheckpoint failed: %v", err)
	}

	err = storage.CreateCheckpoint(context.Background(), scanID, "xss-module", 1)
	if err != nil {
		t.Fatalf("CreateCheckpoint failed: %v", err)
	}

	// Retrieve checkpoints
	checkpoints, err := storage.GetCheckpoints(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetCheckpoints failed: %v", err)
	}

	if len(checkpoints) != 2 {
		t.Fatalf("Expected 2 modules in checkpoints, got %d", len(checkpoints))
	}

	if !checkpoints["sqli-module"][1] {
		t.Error("Expected sqli-module target 1 to be complete")
	}

	if !checkpoints["sqli-module"][2] {
		t.Error("Expected sqli-module target 2 to be complete")
	}

	if !checkpoints["xss-module"][1] {
		t.Error("Expected xss-module target 1 to be complete")
	}
}

func TestStorage_ListScans(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create multiple scans
	for i := 0; i < 5; i++ {
		scan := &atlas.Scan{
			ID:          string(rune('A' + i)),
			Name:        "Test Scan",
			State:       atlas.ScanStatePending,
			WorkspaceID: "workspace-1",
			Target:      atlas.Target{Type: atlas.TargetTypeSingleURL},
			Config:      atlas.ScanConfig{},
		}
		storage.CreateScan(context.Background(), scan)
	}

	// List all scans
	scans, err := storage.ListScans(context.Background(), ScanFilter{})
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}

	if len(scans) != 5 {
		t.Errorf("Expected 5 scans, got %d", len(scans))
	}

	// List with workspace filter
	scans, err = storage.ListScans(context.Background(), ScanFilter{
		WorkspaceID: "workspace-1",
	})
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}

	if len(scans) != 5 {
		t.Errorf("Expected 5 scans in workspace, got %d", len(scans))
	}

	// List with state filter
	scans, err = storage.ListScans(context.Background(), ScanFilter{
		State: atlas.ScanStatePending,
	})
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}

	if len(scans) != 5 {
		t.Errorf("Expected 5 pending scans, got %d", len(scans))
	}
}

func TestStorage_DeleteScan(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	scanID := "test-scan-6"

	// Create scan
	scan := &atlas.Scan{
		ID:     scanID,
		Name:   "Test Scan 6",
		State:  atlas.ScanStatePending,
		Target: atlas.Target{Type: atlas.TargetTypeSingleURL},
		Config: atlas.ScanConfig{},
	}
	storage.CreateScan(context.Background(), scan)

	// Create finding
	finding := &atlas.Finding{
		ID:         "finding-1",
		ScanID:     scanID,
		Type:       "XSS",
		Severity:   atlas.SeverityHigh,
		Confidence: atlas.ConfidenceConfirmed,
		Title:      "Test",
		URL:        "http://test.com",
		DetectedAt: time.Now(),
	}
	storage.StoreFinding(context.Background(), finding)

	// Delete scan
	err := storage.DeleteScan(context.Background(), scanID)
	if err != nil {
		t.Fatalf("DeleteScan failed: %v", err)
	}

	// Verify scan is deleted
	_, err = storage.GetScan(context.Background(), scanID)
	if err == nil {
		t.Error("Expected error getting deleted scan")
	}

	// Verify findings are deleted (cascade)
	findings, err := storage.GetFindingsByScan(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetFindingsByScan failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings after delete, got %d", len(findings))
	}
}

func TestStorage_ForeignKeyConstraints(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Verify foreign keys are enabled
	var fkEnabled int
	err := storage.db.QueryRow("PRAGMA foreign_keys").Scan(&fkEnabled)
	if err != nil {
		t.Fatalf("Failed to check foreign keys: %v", err)
	}

	if fkEnabled != 1 {
		t.Error("Foreign keys are not enabled")
	}
}

// testLogger implements Logger interface for testing
type testLogger struct{}

func (l *testLogger) Debug(msg string, args ...interface{}) {}
func (l *testLogger) Info(msg string, args ...interface{})  {}
func (l *testLogger) Warn(msg string, args ...interface{})  {}
func (l *testLogger) Error(msg string, args ...interface{}) {}
