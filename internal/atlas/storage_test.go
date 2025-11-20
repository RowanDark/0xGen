package atlas

import (
	"context"
	"testing"
	"time"
)

func TestNewMemoryStorage(t *testing.T) {
	storage := NewMemoryStorage()

	if storage == nil {
		t.Fatal("expected non-nil storage")
	}

	if storage.scans == nil {
		t.Error("expected scans map to be initialized")
	}

	if storage.findings == nil {
		t.Error("expected findings map to be initialized")
	}

	if storage.scansByWorkspace == nil {
		t.Error("expected scansByWorkspace map to be initialized")
	}

	if storage.findingsByScan == nil {
		t.Error("expected findingsByScan map to be initialized")
	}
}

func TestMemoryStorage_ListScans(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Initially empty
	scans, err := storage.ListScans(ctx, ScanFilter{})
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(scans) != 0 {
		t.Errorf("expected 0 scans, got %d", len(scans))
	}

	// Add some scans
	scan1 := &Scan{
		ID:          "scan1",
		WorkspaceID: "workspace1",
		State:       "running",
		Tags:        []string{"tag1", "tag2"},
	}
	scan2 := &Scan{
		ID:          "scan2",
		WorkspaceID: "workspace1",
		State:       "completed",
		Tags:        []string{"tag2"},
	}
	scan3 := &Scan{
		ID:          "scan3",
		WorkspaceID: "workspace2",
		State:       "running",
		Tags:        []string{"tag3"},
	}

	storage.StoreScan(ctx, scan1)
	storage.StoreScan(ctx, scan2)
	storage.StoreScan(ctx, scan3)

	// List all scans
	scans, err = storage.ListScans(ctx, ScanFilter{})
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(scans) != 3 {
		t.Errorf("expected 3 scans, got %d", len(scans))
	}

	// Filter by workspace
	scans, err = storage.ListScans(ctx, ScanFilter{WorkspaceID: "workspace1"})
	if err != nil {
		t.Fatalf("ListScans with workspace filter failed: %v", err)
	}
	if len(scans) != 2 {
		t.Errorf("expected 2 scans for workspace1, got %d", len(scans))
	}

	// Filter by state
	scans, err = storage.ListScans(ctx, ScanFilter{State: "running"})
	if err != nil {
		t.Fatalf("ListScans with state filter failed: %v", err)
	}
	if len(scans) != 2 {
		t.Errorf("expected 2 running scans, got %d", len(scans))
	}

	// Filter by tags
	scans, err = storage.ListScans(ctx, ScanFilter{Tags: []string{"tag2"}})
	if err != nil {
		t.Fatalf("ListScans with tag filter failed: %v", err)
	}
	if len(scans) != 2 {
		t.Errorf("expected 2 scans with tag2, got %d", len(scans))
	}

	// Combined filters
	scans, err = storage.ListScans(ctx, ScanFilter{
		WorkspaceID: "workspace1",
		State:       "running",
	})
	if err != nil {
		t.Fatalf("ListScans with combined filters failed: %v", err)
	}
	if len(scans) != 1 {
		t.Errorf("expected 1 scan with combined filters, got %d", len(scans))
	}
}

func TestMemoryStorage_ListScans_Pagination(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Add 10 scans
	for i := 0; i < 10; i++ {
		scan := &Scan{
			ID:    string(rune('a' + i)),
			State: "completed",
		}
		storage.StoreScan(ctx, scan)
	}

	// Test limit
	scans, err := storage.ListScans(ctx, ScanFilter{Limit: 5})
	if err != nil {
		t.Fatalf("ListScans with limit failed: %v", err)
	}
	if len(scans) != 5 {
		t.Errorf("expected 5 scans with limit, got %d", len(scans))
	}

	// Test offset
	scans, err = storage.ListScans(ctx, ScanFilter{Offset: 5})
	if err != nil {
		t.Fatalf("ListScans with offset failed: %v", err)
	}
	if len(scans) != 5 {
		t.Errorf("expected 5 scans with offset, got %d", len(scans))
	}

	// Test offset + limit
	scans, err = storage.ListScans(ctx, ScanFilter{Offset: 3, Limit: 3})
	if err != nil {
		t.Fatalf("ListScans with offset+limit failed: %v", err)
	}
	if len(scans) != 3 {
		t.Errorf("expected 3 scans with offset+limit, got %d", len(scans))
	}

	// Test offset beyond results
	scans, err = storage.ListScans(ctx, ScanFilter{Offset: 100})
	if err != nil {
		t.Fatalf("ListScans with large offset failed: %v", err)
	}
	if len(scans) != 0 {
		t.Errorf("expected 0 scans with large offset, got %d", len(scans))
	}
}

func TestMemoryStorage_UpdateScan(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	scan := &Scan{
		ID:    "scan1",
		State: "running",
	}

	// Store initial scan
	err := storage.StoreScan(ctx, scan)
	if err != nil {
		t.Fatalf("StoreScan failed: %v", err)
	}

	// Update scan
	scan.State = "completed"
	now := time.Now()
	scan.EndTime = &now
	err = storage.UpdateScan(ctx, scan)
	if err != nil {
		t.Fatalf("UpdateScan failed: %v", err)
	}

	// Verify update
	retrieved, err := storage.GetScan(ctx, "scan1")
	if err != nil {
		t.Fatalf("GetScan failed: %v", err)
	}

	if retrieved.State != "completed" {
		t.Errorf("expected state 'completed', got '%s'", retrieved.State)
	}

	if retrieved.EndTime == nil {
		t.Error("expected EndTime to be set")
	}
}

func TestMemoryStorage_UpdateScan_NotFound(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	scan := &Scan{
		ID:    "nonexistent",
		State: "completed",
	}

	err := storage.UpdateScan(ctx, scan)
	if err == nil {
		t.Error("expected error when updating nonexistent scan")
	}
}

func TestMemoryStorage_DeleteScan(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	scan := &Scan{
		ID:          "scan1",
		WorkspaceID: "workspace1",
	}

	// Store scan
	err := storage.StoreScan(ctx, scan)
	if err != nil {
		t.Fatalf("StoreScan failed: %v", err)
	}

	// Store associated finding
	finding := &Finding{
		ID:     "finding1",
		ScanID: "scan1",
	}
	err = storage.StoreFinding(ctx, finding)
	if err != nil {
		t.Fatalf("StoreFinding failed: %v", err)
	}

	// Delete scan
	err = storage.DeleteScan(ctx, "scan1")
	if err != nil {
		t.Fatalf("DeleteScan failed: %v", err)
	}

	// Verify scan is deleted
	_, err = storage.GetScan(ctx, "scan1")
	if err == nil {
		t.Error("expected error when retrieving deleted scan")
	}

	// Verify associated finding is deleted
	_, err = storage.GetFinding(ctx, "finding1")
	if err == nil {
		t.Error("expected error when retrieving finding of deleted scan")
	}

	// Verify workspace index is updated
	scans, err := storage.ListScans(ctx, ScanFilter{WorkspaceID: "workspace1"})
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(scans) != 0 {
		t.Errorf("expected 0 scans in workspace after deletion, got %d", len(scans))
	}
}

func TestMemoryStorage_DeleteScan_NotFound(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	err := storage.DeleteScan(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error when deleting nonexistent scan")
	}
}

func TestMemoryStorage_GetFinding(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	finding := &Finding{
		ID:       "finding1",
		ScanID:   "scan1",
		Type:     "SQLi",
		Severity: SeverityHigh,
	}

	// Store finding
	err := storage.StoreFinding(ctx, finding)
	if err != nil {
		t.Fatalf("StoreFinding failed: %v", err)
	}

	// Retrieve finding
	retrieved, err := storage.GetFinding(ctx, "finding1")
	if err != nil {
		t.Fatalf("GetFinding failed: %v", err)
	}

	if retrieved.ID != "finding1" {
		t.Errorf("expected ID 'finding1', got '%s'", retrieved.ID)
	}

	if retrieved.Type != "SQLi" {
		t.Errorf("expected type 'SQLi', got '%s'", retrieved.Type)
	}

	if retrieved.Severity != SeverityHigh {
		t.Errorf("expected severity High, got %s", retrieved.Severity)
	}
}

func TestMemoryStorage_GetFinding_NotFound(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	_, err := storage.GetFinding(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error when retrieving nonexistent finding")
	}
}

func TestMemoryStorage_ListFindings(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Add findings
	findings := []*Finding{
		{ID: "f1", ScanID: "scan1", Type: "SQLi", Severity: SeverityHigh, Confidence: ConfidenceConfirmed},
		{ID: "f2", ScanID: "scan1", Type: "XSS", Severity: SeverityMedium, Confidence: ConfidenceFirm},
		{ID: "f3", ScanID: "scan2", Type: "SQLi", Severity: SeverityLow, Confidence: ConfidenceTentative},
	}

	for _, f := range findings {
		storage.StoreFinding(ctx, f)
	}

	// List all findings
	result, err := storage.ListFindings(ctx, FindingFilter{})
	if err != nil {
		t.Fatalf("ListFindings failed: %v", err)
	}
	if len(result) != 3 {
		t.Errorf("expected 3 findings, got %d", len(result))
	}

	// Filter by scan
	result, err = storage.ListFindings(ctx, FindingFilter{ScanID: "scan1"})
	if err != nil {
		t.Fatalf("ListFindings with scan filter failed: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 findings for scan1, got %d", len(result))
	}

	// Filter by type
	result, err = storage.ListFindings(ctx, FindingFilter{Type: "SQLi"})
	if err != nil {
		t.Fatalf("ListFindings with type filter failed: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 SQLi findings, got %d", len(result))
	}

	// Filter by severity
	result, err = storage.ListFindings(ctx, FindingFilter{Severity: SeverityHigh})
	if err != nil {
		t.Fatalf("ListFindings with severity filter failed: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 high severity finding, got %d", len(result))
	}

	// Filter by confidence
	result, err = storage.ListFindings(ctx, FindingFilter{Confidence: ConfidenceConfirmed})
	if err != nil {
		t.Fatalf("ListFindings with confidence filter failed: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 confirmed finding, got %d", len(result))
	}

	// Combined filters
	result, err = storage.ListFindings(ctx, FindingFilter{
		ScanID:   "scan1",
		Type:     "SQLi",
		Severity: SeverityHigh,
	})
	if err != nil {
		t.Fatalf("ListFindings with combined filters failed: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 finding with combined filters, got %d", len(result))
	}
}

func TestMemoryStorage_ListFindings_Pagination(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Add 10 findings
	for i := 0; i < 10; i++ {
		finding := &Finding{
			ID:     string(rune('a' + i)),
			ScanID: "scan1",
			Type:   "Test",
		}
		storage.StoreFinding(ctx, finding)
	}

	// Test limit
	findings, err := storage.ListFindings(ctx, FindingFilter{Limit: 5})
	if err != nil {
		t.Fatalf("ListFindings with limit failed: %v", err)
	}
	if len(findings) != 5 {
		t.Errorf("expected 5 findings with limit, got %d", len(findings))
	}

	// Test offset
	findings, err = storage.ListFindings(ctx, FindingFilter{Offset: 5})
	if err != nil {
		t.Fatalf("ListFindings with offset failed: %v", err)
	}
	if len(findings) != 5 {
		t.Errorf("expected 5 findings with offset, got %d", len(findings))
	}

	// Test offset beyond results
	findings, err = storage.ListFindings(ctx, FindingFilter{Offset: 100})
	if err != nil {
		t.Fatalf("ListFindings with large offset failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with large offset, got %d", len(findings))
	}
}

func TestMemoryStorage_GetStats(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Initially empty
	scansCount, findingsCount := storage.GetStats()
	if scansCount != 0 {
		t.Errorf("expected 0 scans, got %d", scansCount)
	}
	if findingsCount != 0 {
		t.Errorf("expected 0 findings, got %d", findingsCount)
	}

	// Add some scans and findings
	storage.StoreScan(ctx, &Scan{ID: "scan1"})
	storage.StoreScan(ctx, &Scan{ID: "scan2"})
	storage.StoreFinding(ctx, &Finding{ID: "f1", ScanID: "scan1"})
	storage.StoreFinding(ctx, &Finding{ID: "f2", ScanID: "scan1"})
	storage.StoreFinding(ctx, &Finding{ID: "f3", ScanID: "scan2"})

	scansCount, findingsCount = storage.GetStats()
	if scansCount != 2 {
		t.Errorf("expected 2 scans, got %d", scansCount)
	}
	if findingsCount != 3 {
		t.Errorf("expected 3 findings, got %d", findingsCount)
	}
}

func TestMemoryStorage_Clear(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Add some data
	storage.StoreScan(ctx, &Scan{ID: "scan1", WorkspaceID: "ws1"})
	storage.StoreFinding(ctx, &Finding{ID: "f1", ScanID: "scan1"})

	scansCount, findingsCount := storage.GetStats()
	if scansCount != 1 || findingsCount != 1 {
		t.Fatal("failed to add initial data")
	}

	// Clear storage
	storage.Clear()

	// Verify everything is cleared
	scansCount, findingsCount = storage.GetStats()
	if scansCount != 0 {
		t.Errorf("expected 0 scans after clear, got %d", scansCount)
	}
	if findingsCount != 0 {
		t.Errorf("expected 0 findings after clear, got %d", findingsCount)
	}

	// Verify indices are cleared
	scans, err := storage.ListScans(ctx, ScanFilter{WorkspaceID: "ws1"})
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(scans) != 0 {
		t.Errorf("expected 0 scans in workspace after clear, got %d", len(scans))
	}
}

func TestMemoryStorage_StoreScanTargets(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	targets := []*ScanTarget{
		{URL: "http://example.com/1", Method: "GET"},
		{URL: "http://example.com/2", Method: "POST"},
	}

	// Should not error (no-op)
	err := storage.StoreScanTargets(ctx, "scan1", targets)
	if err != nil {
		t.Errorf("StoreScanTargets failed: %v", err)
	}
}

func TestMemoryStorage_GetUntestedTargets(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Should return empty slice (no-op)
	targets, err := storage.GetUntestedTargets(ctx, "scan1")
	if err != nil {
		t.Errorf("GetUntestedTargets failed: %v", err)
	}

	if len(targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(targets))
	}
}

func TestMemoryStorage_MarkTargetTested(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Should not error (no-op)
	err := storage.MarkTargetTested(ctx, "scan1", "http://example.com")
	if err != nil {
		t.Errorf("MarkTargetTested failed: %v", err)
	}
}

func TestMemoryStorage_CreateCheckpoint(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Should not error (no-op)
	err := storage.CreateCheckpoint(ctx, "scan1", "module1", 0)
	if err != nil {
		t.Errorf("CreateCheckpoint failed: %v", err)
	}
}

func TestMemoryStorage_GetCheckpoints(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Should return empty map (no-op)
	checkpoints, err := storage.GetCheckpoints(ctx, "scan1")
	if err != nil {
		t.Errorf("GetCheckpoints failed: %v", err)
	}

	if len(checkpoints) != 0 {
		t.Errorf("expected 0 checkpoints, got %d", len(checkpoints))
	}
}

func TestMemoryStorage_GetFindingsByScan(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	// Add findings
	storage.StoreFinding(ctx, &Finding{ID: "f1", ScanID: "scan1", Type: "SQLi"})
	storage.StoreFinding(ctx, &Finding{ID: "f2", ScanID: "scan1", Type: "XSS"})
	storage.StoreFinding(ctx, &Finding{ID: "f3", ScanID: "scan2", Type: "SSRF"})

	// Get findings for scan1
	findings, err := storage.GetFindingsByScan(ctx, "scan1")
	if err != nil {
		t.Fatalf("GetFindingsByScan failed: %v", err)
	}

	if len(findings) != 2 {
		t.Errorf("expected 2 findings for scan1, got %d", len(findings))
	}

	// Verify correct findings returned
	for _, f := range findings {
		if f.ScanID != "scan1" {
			t.Errorf("expected ScanID 'scan1', got '%s'", f.ScanID)
		}
	}

	// Get findings for scan2
	findings, err = storage.GetFindingsByScan(ctx, "scan2")
	if err != nil {
		t.Fatalf("GetFindingsByScan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("expected 1 finding for scan2, got %d", len(findings))
	}

	// Get findings for nonexistent scan
	findings, err = storage.GetFindingsByScan(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetFindingsByScan failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nonexistent scan, got %d", len(findings))
	}
}
