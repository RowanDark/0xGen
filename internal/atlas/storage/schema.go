package storage

import (
	"database/sql"
	"fmt"
)

const schemaSQL = `
-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_urls TEXT, -- JSON array
    target_scope TEXT, -- JSON object
    config TEXT NOT NULL, -- JSON
    state TEXT NOT NULL,
    created_by TEXT,
    workspace_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_ms INTEGER,

    -- Progress
    phase TEXT,
    current_module TEXT,
    urls_discovered INTEGER DEFAULT 0,
    urls_tested INTEGER DEFAULT 0,
    urls_remaining INTEGER DEFAULT 0,
    requests_sent INTEGER DEFAULT 0,
    findings_found INTEGER DEFAULT 0,
    percent_complete REAL DEFAULT 0,

    -- Metadata
    tags TEXT, -- JSON array
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_state ON scans(state);
CREATE INDEX IF NOT EXISTS idx_scans_workspace ON scans(workspace_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,

    -- Location
    url TEXT NOT NULL,
    method TEXT,
    parameter TEXT,
    location TEXT, -- query, body, header, cookie, path

    -- Evidence
    request TEXT,
    response TEXT,
    payload TEXT,
    proof TEXT,

    -- Classification
    cwe TEXT,
    owasp TEXT,
    cvss REAL,

    -- Remediation
    remediation TEXT,
    reference_links TEXT, -- JSON array

    -- Metadata
    detected_by TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,

    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
CREATE INDEX IF NOT EXISTS idx_findings_url ON findings(url);

-- Scan targets (for resumability)
CREATE TABLE IF NOT EXISTS scan_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    parameters TEXT, -- JSON
    headers TEXT, -- JSON
    body TEXT,
    tested BOOLEAN DEFAULT FALSE,
    tested_at TIMESTAMP,

    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_targets_scan ON scan_targets(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_targets_tested ON scan_targets(scan_id, tested);

-- Scan checkpoints (for fine-grained resumability)
CREATE TABLE IF NOT EXISTS scan_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    module_name TEXT NOT NULL,
    target_id INTEGER NOT NULL,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES scan_targets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_checkpoints_scan ON scan_checkpoints(scan_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_checkpoints_unique ON scan_checkpoints(scan_id, module_name, target_id);
`

// InitializeSchema creates all necessary tables and indices.
func InitializeSchema(db *sql.DB) error {
	_, err := db.Exec(schemaSQL)
	if err != nil {
		return fmt.Errorf("initialize schema: %w", err)
	}

	// Enable foreign keys
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	return nil
}
