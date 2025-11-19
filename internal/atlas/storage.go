package atlas

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryStorage provides an in-memory implementation of Storage.
type MemoryStorage struct {
	mu       sync.RWMutex
	scans    map[string]*Scan
	findings map[string]*Finding

	// Indices
	scansByWorkspace map[string][]string   // workspaceID -> []scanID
	findingsByScan   map[string][]string   // scanID -> []findingID
}

// NewMemoryStorage creates a new in-memory storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		scans:            make(map[string]*Scan),
		findings:         make(map[string]*Finding),
		scansByWorkspace: make(map[string][]string),
		findingsByScan:   make(map[string][]string),
	}
}

// StoreScan persists a scan to storage.
func (s *MemoryStorage) StoreScan(ctx context.Context, scan *Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Make a copy to avoid external modifications
	scanCopy := *scan
	scanCopy.Findings = make([]*Finding, len(scan.Findings))
	copy(scanCopy.Findings, scan.Findings)

	s.scans[scan.ID] = &scanCopy

	// Update workspace index
	if scan.WorkspaceID != "" {
		found := false
		for _, id := range s.scansByWorkspace[scan.WorkspaceID] {
			if id == scan.ID {
				found = true
				break
			}
		}
		if !found {
			s.scansByWorkspace[scan.WorkspaceID] = append(
				s.scansByWorkspace[scan.WorkspaceID],
				scan.ID,
			)
		}
	}

	return nil
}

// GetScan retrieves a scan by ID.
func (s *MemoryStorage) GetScan(ctx context.Context, scanID string) (*Scan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	scan, ok := s.scans[scanID]
	if !ok {
		return nil, fmt.Errorf("scan %s not found", scanID)
	}

	// Return a copy
	scanCopy := *scan
	scanCopy.Findings = make([]*Finding, len(scan.Findings))
	copy(scanCopy.Findings, scan.Findings)

	return &scanCopy, nil
}

// ListScans returns scans matching the filter.
func (s *MemoryStorage) ListScans(ctx context.Context, filter ScanFilter) ([]*Scan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Scan

	// If filtering by workspace, use index
	var scanIDs []string
	if filter.WorkspaceID != "" {
		scanIDs = s.scansByWorkspace[filter.WorkspaceID]
	} else {
		for id := range s.scans {
			scanIDs = append(scanIDs, id)
		}
	}

	for _, id := range scanIDs {
		scan := s.scans[id]
		if scan == nil {
			continue
		}

		// Apply state filter
		if filter.State != "" && scan.State != filter.State {
			continue
		}

		// Apply tag filter
		if len(filter.Tags) > 0 {
			hasTag := false
			for _, filterTag := range filter.Tags {
				for _, scanTag := range scan.Tags {
					if scanTag == filterTag {
						hasTag = true
						break
					}
				}
				if hasTag {
					break
				}
			}
			if !hasTag {
				continue
			}
		}

		// Make a copy
		scanCopy := *scan
		scanCopy.Findings = make([]*Finding, len(scan.Findings))
		copy(scanCopy.Findings, scan.Findings)
		result = append(result, &scanCopy)
	}

	// Apply pagination
	if filter.Offset > 0 {
		if filter.Offset >= len(result) {
			return []*Scan{}, nil
		}
		result = result[filter.Offset:]
	}

	if filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}

	return result, nil
}

// UpdateScan updates an existing scan.
func (s *MemoryStorage) UpdateScan(ctx context.Context, scan *Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.scans[scan.ID]; !ok {
		return fmt.Errorf("scan %s not found", scan.ID)
	}

	// Make a copy
	scanCopy := *scan
	scanCopy.Findings = make([]*Finding, len(scan.Findings))
	copy(scanCopy.Findings, scan.Findings)

	s.scans[scan.ID] = &scanCopy
	return nil
}

// DeleteScan removes a scan from storage.
func (s *MemoryStorage) DeleteScan(ctx context.Context, scanID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	scan, ok := s.scans[scanID]
	if !ok {
		return fmt.Errorf("scan %s not found", scanID)
	}

	// Remove from workspace index
	if scan.WorkspaceID != "" {
		ids := s.scansByWorkspace[scan.WorkspaceID]
		for i, id := range ids {
			if id == scanID {
				s.scansByWorkspace[scan.WorkspaceID] = append(ids[:i], ids[i+1:]...)
				break
			}
		}
	}

	// Remove associated findings
	for _, findingID := range s.findingsByScan[scanID] {
		delete(s.findings, findingID)
	}
	delete(s.findingsByScan, scanID)

	delete(s.scans, scanID)
	return nil
}

// StoreFinding persists a finding to storage.
func (s *MemoryStorage) StoreFinding(ctx context.Context, finding *Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate ID if not set
	if finding.ID == "" {
		finding.ID = fmt.Sprintf("finding-%d", time.Now().UnixNano())
	}

	// Make a copy
	findingCopy := *finding
	s.findings[finding.ID] = &findingCopy

	// Update scan index
	if finding.ScanID != "" {
		s.findingsByScan[finding.ScanID] = append(
			s.findingsByScan[finding.ScanID],
			finding.ID,
		)
	}

	return nil
}

// GetFinding retrieves a finding by ID.
func (s *MemoryStorage) GetFinding(ctx context.Context, findingID string) (*Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	finding, ok := s.findings[findingID]
	if !ok {
		return nil, fmt.Errorf("finding %s not found", findingID)
	}

	// Return a copy
	findingCopy := *finding
	return &findingCopy, nil
}

// ListFindings returns findings matching the filter.
func (s *MemoryStorage) ListFindings(ctx context.Context, filter FindingFilter) ([]*Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Finding

	// If filtering by scan, use index
	var findingIDs []string
	if filter.ScanID != "" {
		findingIDs = s.findingsByScan[filter.ScanID]
	} else {
		for id := range s.findings {
			findingIDs = append(findingIDs, id)
		}
	}

	for _, id := range findingIDs {
		finding := s.findings[id]
		if finding == nil {
			continue
		}

		// Apply type filter
		if filter.Type != "" && finding.Type != filter.Type {
			continue
		}

		// Apply severity filter
		if filter.Severity != "" && finding.Severity != filter.Severity {
			continue
		}

		// Apply confidence filter
		if filter.Confidence != "" && finding.Confidence != filter.Confidence {
			continue
		}

		// Make a copy
		findingCopy := *finding
		result = append(result, &findingCopy)
	}

	// Apply pagination
	if filter.Offset > 0 {
		if filter.Offset >= len(result) {
			return []*Finding{}, nil
		}
		result = result[filter.Offset:]
	}

	if filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}

	return result, nil
}

// GetStats returns storage statistics.
func (s *MemoryStorage) GetStats() (scans, findings int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.scans), len(s.findings)
}

// Clear removes all data from storage.
func (s *MemoryStorage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.scans = make(map[string]*Scan)
	s.findings = make(map[string]*Finding)
	s.scansByWorkspace = make(map[string][]string)
	s.findingsByScan = make(map[string][]string)
}
