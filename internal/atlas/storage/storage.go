package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/RowanDark/0xgen/internal/atlas"
	_ "github.com/mattn/go-sqlite3"
)

// Storage provides persistent storage for scans and findings.
type Storage struct {
	db     *sql.DB
	logger atlas.Logger
}

// New creates a new storage instance.
func New(dbPath string, logger atlas.Logger) (*Storage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Initialize schema
	if err := InitializeSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	return &Storage{
		db:     db,
		logger: logger,
	}, nil
}

// Close closes the database connection.
func (s *Storage) Close() error {
	return s.db.Close()
}

// CreateScan creates a new scan record.
func (s *Storage) CreateScan(ctx context.Context, scan *atlas.Scan) error {
	targetURLs, _ := json.Marshal(scan.Target.URLs)
	targetScope, _ := json.Marshal(scan.Target.Scope)
	config, _ := json.Marshal(scan.Config)
	tags, _ := json.Marshal(scan.Tags)

	_, err := s.db.ExecContext(ctx, `
        INSERT INTO scans (
            id, name, target_type, target_urls, target_scope, config,
            state, created_by, workspace_id, tags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, scan.ID, scan.Name, scan.Target.Type, string(targetURLs),
		string(targetScope), string(config), scan.State,
		scan.CreatedBy, scan.WorkspaceID, string(tags))

	return err
}

// UpdateScan updates scan state and progress.
func (s *Storage) UpdateScan(ctx context.Context, scan *atlas.Scan) error {
	var startedAt, completedAt interface{}
	if !scan.StartTime.IsZero() {
		startedAt = scan.StartTime
	}
	if scan.EndTime != nil {
		completedAt = *scan.EndTime
	}

	_, err := s.db.ExecContext(ctx, `
        UPDATE scans SET
            state = ?,
            started_at = ?,
            completed_at = ?,
            duration_ms = ?,
            phase = ?,
            current_module = ?,
            urls_discovered = ?,
            urls_tested = ?,
            urls_remaining = ?,
            requests_sent = ?,
            findings_found = ?,
            percent_complete = ?
        WHERE id = ?
    `, scan.State, startedAt, completedAt, scan.Duration.Milliseconds(),
		scan.Progress.Phase, scan.Progress.CurrentModule,
		scan.Progress.URLsDiscovered, scan.Progress.URLsTested,
		scan.Progress.URLsRemaining, scan.Progress.RequestsSent,
		scan.Progress.FindingsFound, scan.Progress.PercentComplete,
		scan.ID)

	return err
}

// GetScan retrieves a scan by ID.
func (s *Storage) GetScan(ctx context.Context, scanID string) (*atlas.Scan, error) {
	var scan atlas.Scan
	var targetURLsJSON, targetScopeJSON, configJSON, tagsJSON sql.NullString
	var startedAt, completedAt sql.NullTime
	var durationMS sql.NullInt64
	var phase, currentModule sql.NullString
	var createdAt time.Time

	err := s.db.QueryRowContext(ctx, `
        SELECT id, name, target_type, target_urls, target_scope, config,
               state, created_by, workspace_id, created_at,
               started_at, completed_at, duration_ms,
               phase, current_module, urls_discovered, urls_tested,
               urls_remaining, requests_sent, findings_found,
               percent_complete, tags
        FROM scans WHERE id = ?
    `, scanID).Scan(
		&scan.ID, &scan.Name, &scan.Target.Type, &targetURLsJSON,
		&targetScopeJSON, &configJSON, &scan.State, &scan.CreatedBy,
		&scan.WorkspaceID, &createdAt, &startedAt, &completedAt,
		&durationMS, &phase, &currentModule,
		&scan.Progress.URLsDiscovered, &scan.Progress.URLsTested,
		&scan.Progress.URLsRemaining, &scan.Progress.RequestsSent,
		&scan.Progress.FindingsFound, &scan.Progress.PercentComplete,
		&tagsJSON,
	)

	if err != nil {
		return nil, err
	}

	// Unmarshal JSON fields
	if targetURLsJSON.Valid {
		if err := json.Unmarshal([]byte(targetURLsJSON.String), &scan.Target.URLs); err != nil {
			return nil, fmt.Errorf("unmarshal target URLs: %w", err)
		}
	}
	if targetScopeJSON.Valid {
		if err := json.Unmarshal([]byte(targetScopeJSON.String), &scan.Target.Scope); err != nil {
			return nil, fmt.Errorf("unmarshal target scope: %w", err)
		}
	}
	if configJSON.Valid {
		if err := json.Unmarshal([]byte(configJSON.String), &scan.Config); err != nil {
			return nil, fmt.Errorf("unmarshal config: %w", err)
		}
	}
	if tagsJSON.Valid {
		if err := json.Unmarshal([]byte(tagsJSON.String), &scan.Tags); err != nil {
			return nil, fmt.Errorf("unmarshal tags: %w", err)
		}
	}

	if phase.Valid {
		scan.Progress.Phase = phase.String
	}
	if currentModule.Valid {
		scan.Progress.CurrentModule = currentModule.String
	}

	if startedAt.Valid {
		scan.StartTime = startedAt.Time
	}
	if completedAt.Valid {
		scan.EndTime = &completedAt.Time
	}
	if durationMS.Valid {
		scan.Duration = time.Duration(durationMS.Int64) * time.Millisecond
	}

	// Load findings
	scan.Findings, err = s.GetFindingsByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}

	return &scan, nil
}

// ListScans lists all scans with optional filters.
func (s *Storage) ListScans(ctx context.Context, filter ScanFilter) ([]*atlas.Scan, error) {
	query := `SELECT id, name, state, created_at, started_at, completed_at,
                     findings_found, percent_complete
              FROM scans WHERE 1=1`
	args := []interface{}{}

	if filter.WorkspaceID != "" {
		query += " AND workspace_id = ?"
		args = append(args, filter.WorkspaceID)
	}

	if filter.State != "" {
		query += " AND state = ?"
		args = append(args, filter.State)
	}

	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*atlas.Scan
	for rows.Next() {
		var scan atlas.Scan
		var createdAt time.Time
		var startedAt, completedAt sql.NullTime

		err := rows.Scan(
			&scan.ID, &scan.Name, &scan.State, &createdAt,
			&startedAt, &completedAt, &scan.Progress.FindingsFound,
			&scan.Progress.PercentComplete,
		)
		if err != nil {
			return nil, err
		}

		if startedAt.Valid {
			scan.StartTime = startedAt.Time
		}
		if completedAt.Valid {
			scan.EndTime = &completedAt.Time
		}

		scans = append(scans, &scan)
	}

	return scans, rows.Err()
}

// ScanFilter contains filters for listing scans.
type ScanFilter struct {
	WorkspaceID string
	State       atlas.ScanState
	Limit       int
}

// StoreFinding stores a finding.
func (s *Storage) StoreFinding(ctx context.Context, finding *atlas.Finding) error {
	references, _ := json.Marshal(finding.References)

	_, err := s.db.ExecContext(ctx, `
        INSERT INTO findings (
            id, scan_id, type, severity, confidence, title, description,
            url, method, parameter, location, request, response,
            payload, proof, cwe, owasp, cvss, remediation, reference_links,
            detected_by, detected_at, verified, false_positive
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, finding.ID, finding.ScanID, finding.Type, finding.Severity,
		finding.Confidence, finding.Title, finding.Description,
		finding.URL, finding.Method, finding.Parameter, finding.Location,
		finding.Request, finding.Response, finding.Payload, finding.Proof,
		finding.CWE, finding.OWASP, finding.CVSS, finding.Remediation,
		string(references), finding.DetectedBy, finding.DetectedAt,
		finding.Verified, finding.FalsePositive)

	return err
}

// GetFindingsByScan retrieves all findings for a scan.
func (s *Storage) GetFindingsByScan(ctx context.Context, scanID string) ([]*atlas.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, scan_id, type, severity, confidence, title, description,
               url, method, parameter, location, request, response,
               payload, proof, cwe, owasp, cvss, remediation, reference_links,
               detected_by, detected_at, verified, false_positive
        FROM findings WHERE scan_id = ?
        ORDER BY detected_at DESC
    `, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*atlas.Finding
	for rows.Next() {
		var f atlas.Finding
		var referencesJSON sql.NullString

		err := rows.Scan(
			&f.ID, &f.ScanID, &f.Type, &f.Severity, &f.Confidence,
			&f.Title, &f.Description, &f.URL, &f.Method, &f.Parameter,
			&f.Location, &f.Request, &f.Response, &f.Payload, &f.Proof,
			&f.CWE, &f.OWASP, &f.CVSS, &f.Remediation, &referencesJSON,
			&f.DetectedBy, &f.DetectedAt, &f.Verified, &f.FalsePositive,
		)
		if err != nil {
			return nil, err
		}

		if referencesJSON.Valid {
			if err := json.Unmarshal([]byte(referencesJSON.String), &f.References); err != nil {
				return nil, fmt.Errorf("unmarshal finding %d references: %w", f.ID, err)
			}
		}

		findings = append(findings, &f)
	}

	return findings, rows.Err()
}

// StoreScanTargets stores targets for resumability.
func (s *Storage) StoreScanTargets(ctx context.Context, scanID string, targets []*atlas.ScanTarget) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO scan_targets (scan_id, url, method, parameters, headers, body)
        VALUES (?, ?, ?, ?, ?, ?)
    `)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, target := range targets {
		params, _ := json.Marshal(target.Parameters)
		headers, _ := json.Marshal(target.Headers)

		_, err := stmt.ExecContext(ctx, scanID, target.URL, target.Method,
			string(params), string(headers), target.Body)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetUntestedTargets retrieves targets that haven't been tested yet.
func (s *Storage) GetUntestedTargets(ctx context.Context, scanID string) ([]*atlas.ScanTarget, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, url, method, parameters, headers, body
        FROM scan_targets
        WHERE scan_id = ? AND tested = FALSE
    `, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []*atlas.ScanTarget
	for rows.Next() {
		var target atlas.ScanTarget
		var id int
		var paramsJSON, headersJSON sql.NullString

		err := rows.Scan(&id, &target.URL, &target.Method, &paramsJSON, &headersJSON, &target.Body)
		if err != nil {
			return nil, err
		}

		if paramsJSON.Valid {
			if err := json.Unmarshal([]byte(paramsJSON.String), &target.Parameters); err != nil {
				return nil, fmt.Errorf("unmarshal target parameters: %w", err)
			}
		}
		if headersJSON.Valid {
			if err := json.Unmarshal([]byte(headersJSON.String), &target.Headers); err != nil {
				return nil, fmt.Errorf("unmarshal target headers: %w", err)
			}
		}

		targets = append(targets, &target)
	}

	return targets, rows.Err()
}

// MarkTargetTested marks a target as tested.
func (s *Storage) MarkTargetTested(ctx context.Context, scanID string, targetURL string) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE scan_targets SET tested = TRUE, tested_at = CURRENT_TIMESTAMP
        WHERE scan_id = ? AND url = ?
    `, scanID, targetURL)
	return err
}

// CreateCheckpoint records that a module completed testing a target.
func (s *Storage) CreateCheckpoint(ctx context.Context, scanID, moduleName string, targetID int) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT OR IGNORE INTO scan_checkpoints (scan_id, module_name, target_id)
        VALUES (?, ?, ?)
    `, scanID, moduleName, targetID)
	return err
}

// GetCheckpoints retrieves completed checkpoints.
func (s *Storage) GetCheckpoints(ctx context.Context, scanID string) (map[string]map[int]bool, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT module_name, target_id
        FROM scan_checkpoints
        WHERE scan_id = ?
    `, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Map: module_name -> target_id -> completed
	checkpoints := make(map[string]map[int]bool)

	for rows.Next() {
		var moduleName string
		var targetID int

		err := rows.Scan(&moduleName, &targetID)
		if err != nil {
			return nil, err
		}

		if checkpoints[moduleName] == nil {
			checkpoints[moduleName] = make(map[int]bool)
		}
		checkpoints[moduleName][targetID] = true
	}

	return checkpoints, rows.Err()
}

// DeleteScan deletes a scan and all associated data.
func (s *Storage) DeleteScan(ctx context.Context, scanID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM scans WHERE id = ?", scanID)
	return err
}
