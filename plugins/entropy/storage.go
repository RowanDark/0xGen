package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // SQLite driver
)

// Storage handles database operations for token samples
type Storage struct {
	db *sql.DB
}

// NewStorage creates a new storage instance
func NewStorage(dbPath string) (*Storage, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}

	// Enable foreign key constraints
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	// Verify foreign keys are enabled
	var fkEnabled int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&fkEnabled); err != nil {
		db.Close()
		return nil, fmt.Errorf("verify foreign keys: %w", err)
	}
	if fkEnabled != 1 {
		db.Close()
		return nil, fmt.Errorf("foreign keys could not be enabled")
	}

	storage := &Storage{db: db}
	if err := storage.createTables(); err != nil {
		db.Close()
		return nil, err
	}

	return storage, nil
}

// createTables initializes the database schema
func (s *Storage) createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS capture_sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		extractor_pattern TEXT NOT NULL,
		extractor_location TEXT NOT NULL,
		extractor_name TEXT NOT NULL,
		started_at TIMESTAMP NOT NULL,
		completed_at TIMESTAMP,
		paused_at TIMESTAMP,
		token_count INTEGER DEFAULT 0,
		status TEXT DEFAULT 'active',
		target_count INTEGER DEFAULT 0,
		timeout_seconds INTEGER DEFAULT 0,
		stop_reason TEXT,
		last_analyzed_at TIMESTAMP,
		last_analysis_count INTEGER DEFAULT 0,
		analysis_interval INTEGER DEFAULT 50,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS token_samples (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		capture_session_id INTEGER NOT NULL,
		token_value TEXT NOT NULL,
		token_length INTEGER NOT NULL,
		captured_at TIMESTAMP NOT NULL,
		source_request_id TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (capture_session_id) REFERENCES capture_sessions(id)
	);

	CREATE INDEX IF NOT EXISTS idx_session ON token_samples(capture_session_id);
	CREATE INDEX IF NOT EXISTS idx_captured_at ON token_samples(captured_at);
	CREATE INDEX IF NOT EXISTS idx_token_value ON token_samples(token_value);
	CREATE INDEX IF NOT EXISTS idx_session_status ON capture_sessions(status);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}

	// Migrate existing tables to add new columns if needed
	if err := s.migrateSchema(); err != nil {
		return fmt.Errorf("migrate schema: %w", err)
	}

	return nil
}

// migrateSchema adds new columns to existing tables
func (s *Storage) migrateSchema() error {
	// Check if columns exist and add them if they don't
	migrations := []string{
		"ALTER TABLE capture_sessions ADD COLUMN status TEXT DEFAULT 'active'",
		"ALTER TABLE capture_sessions ADD COLUMN paused_at TIMESTAMP",
		"ALTER TABLE capture_sessions ADD COLUMN target_count INTEGER DEFAULT 0",
		"ALTER TABLE capture_sessions ADD COLUMN timeout_seconds INTEGER DEFAULT 0",
		"ALTER TABLE capture_sessions ADD COLUMN stop_reason TEXT",
		"ALTER TABLE capture_sessions ADD COLUMN last_analyzed_at TIMESTAMP",
		"ALTER TABLE capture_sessions ADD COLUMN last_analysis_count INTEGER DEFAULT 0",
		"ALTER TABLE capture_sessions ADD COLUMN analysis_interval INTEGER DEFAULT 50",
	}

	for _, migration := range migrations {
		// SQLite doesn't have "IF NOT EXISTS" for ALTER TABLE, so we ignore errors if column exists
		s.db.Exec(migration)
	}

	return nil
}

// CreateSession creates a new capture session with optional parameters
func (s *Storage) CreateSession(name string, extractor TokenExtractor, targetCount int, timeout time.Duration) (*CaptureSession, error) {
	now := time.Now().UTC()
	timeoutSeconds := int64(timeout.Seconds())

	result, err := s.db.Exec(`
		INSERT INTO capture_sessions (
			name, extractor_pattern, extractor_location, extractor_name,
			started_at, status, target_count, timeout_seconds, analysis_interval
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, name, extractor.Pattern, extractor.Location, extractor.Name,
		now, CaptureStatusActive, targetCount, timeoutSeconds, 50)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("get session id: %w", err)
	}

	return &CaptureSession{
		ID:               id,
		Name:             name,
		Extractor:        extractor,
		StartedAt:        now,
		Status:           CaptureStatusActive,
		TargetCount:      targetCount,
		Timeout:          timeout,
		AnalysisInterval: 50,
	}, nil
}

// StoreToken stores a captured token sample atomically with token count update
func (s *Storage) StoreToken(sample TokenSample) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() // Rollback if not committed

	// Insert token
	result, err := tx.ExecContext(ctx, `
		INSERT INTO token_samples (capture_session_id, token_value, token_length, captured_at, source_request_id)
		VALUES (?, ?, ?, ?, ?)
	`, sample.CaptureSessionID, sample.TokenValue, sample.TokenLength, sample.CapturedAt, sample.SourceRequestID)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}

	// Get the inserted ID
	sample.ID, err = result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}

	// Update session token count
	_, err = tx.ExecContext(ctx, `
		UPDATE capture_sessions
		SET token_count = token_count + 1
		WHERE id = ?
	`, sample.CaptureSessionID)
	if err != nil {
		return fmt.Errorf("update token count: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// GetTokens retrieves all tokens for a session
func (s *Storage) GetTokens(sessionID int64) ([]TokenSample, error) {
	rows, err := s.db.Query(`
		SELECT id, capture_session_id, token_value, token_length, captured_at, source_request_id
		FROM token_samples
		WHERE capture_session_id = ?
		ORDER BY captured_at ASC
	`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("query tokens: %w", err)
	}
	defer rows.Close()

	var tokens []TokenSample
	for rows.Next() {
		var t TokenSample
		var sourceID sql.NullString
		if err := rows.Scan(&t.ID, &t.CaptureSessionID, &t.TokenValue, &t.TokenLength, &t.CapturedAt, &sourceID); err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		if sourceID.Valid {
			t.SourceRequestID = sourceID.String
		}
		tokens = append(tokens, t)
	}

	return tokens, nil
}

// GetSession retrieves a capture session by ID
func (s *Storage) GetSession(sessionID int64) (*CaptureSession, error) {
	var session CaptureSession
	var completedAt, pausedAt, lastAnalyzedAt sql.NullTime
	var stopReason sql.NullString
	var extractor TokenExtractor
	var timeoutSeconds int64

	err := s.db.QueryRow(`
		SELECT id, name, extractor_pattern, extractor_location, extractor_name,
		       started_at, completed_at, paused_at, token_count, status,
		       target_count, timeout_seconds, stop_reason,
		       last_analyzed_at, last_analysis_count, analysis_interval
		FROM capture_sessions
		WHERE id = ?
	`, sessionID).Scan(
		&session.ID, &session.Name,
		&extractor.Pattern, &extractor.Location, &extractor.Name,
		&session.StartedAt, &completedAt, &pausedAt, &session.TokenCount, &session.Status,
		&session.TargetCount, &timeoutSeconds, &stopReason,
		&lastAnalyzedAt, &session.LastAnalysisCount, &session.AnalysisInterval,
	)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}

	session.Extractor = extractor
	session.Timeout = time.Duration(timeoutSeconds) * time.Second

	if completedAt.Valid {
		session.CompletedAt = &completedAt.Time
	}
	if pausedAt.Valid {
		session.PausedAt = &pausedAt.Time
	}
	if lastAnalyzedAt.Valid {
		session.LastAnalyzedAt = &lastAnalyzedAt.Time
	}
	if stopReason.Valid {
		session.StopReason = StopReason(stopReason.String)
	}

	return &session, nil
}

// UpdateSession updates a session's state in the database
func (s *Storage) UpdateSession(session *CaptureSession) error {
	var timeoutSeconds int64
	if session.Timeout > 0 {
		timeoutSeconds = int64(session.Timeout.Seconds())
	}

	_, err := s.db.Exec(`
		UPDATE capture_sessions
		SET status = ?, paused_at = ?, completed_at = ?, stop_reason = ?,
		    target_count = ?, timeout_seconds = ?,
		    last_analyzed_at = ?, last_analysis_count = ?, analysis_interval = ?
		WHERE id = ?
	`, session.Status, session.PausedAt, session.CompletedAt, session.StopReason,
		session.TargetCount, timeoutSeconds,
		session.LastAnalyzedAt, session.LastAnalysisCount, session.AnalysisInterval,
		session.ID)

	if err != nil {
		return fmt.Errorf("update session: %w", err)
	}
	return nil
}

// PauseSession pauses an active session
func (s *Storage) PauseSession(sessionID int64) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		UPDATE capture_sessions
		SET status = ?, paused_at = ?
		WHERE id = ? AND status = ?
	`, CaptureStatusPaused, now, sessionID, CaptureStatusActive)
	if err != nil {
		return fmt.Errorf("pause session: %w", err)
	}
	return nil
}

// ResumeSession resumes a paused session
func (s *Storage) ResumeSession(sessionID int64) error {
	_, err := s.db.Exec(`
		UPDATE capture_sessions
		SET status = ?, paused_at = NULL
		WHERE id = ? AND status = ?
	`, CaptureStatusActive, sessionID, CaptureStatusPaused)
	if err != nil {
		return fmt.Errorf("resume session: %w", err)
	}
	return nil
}

// StopSession stops a session with the given reason
func (s *Storage) StopSession(sessionID int64, reason StopReason) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		UPDATE capture_sessions
		SET status = ?, completed_at = ?, stop_reason = ?
		WHERE id = ? AND status != ?
	`, CaptureStatusStopped, now, reason, sessionID, CaptureStatusStopped)
	if err != nil {
		return fmt.Errorf("stop session: %w", err)
	}
	return nil
}

// GetActiveSessions retrieves all active capture sessions
func (s *Storage) GetActiveSessions() ([]*CaptureSession, error) {
	rows, err := s.db.Query(`
		SELECT id, name, extractor_pattern, extractor_location, extractor_name,
		       started_at, completed_at, paused_at, token_count, status,
		       target_count, timeout_seconds, stop_reason,
		       last_analyzed_at, last_analysis_count, analysis_interval
		FROM capture_sessions
		WHERE status = ?
		ORDER BY started_at DESC
	`, CaptureStatusActive)
	if err != nil {
		return nil, fmt.Errorf("query active sessions: %w", err)
	}
	defer rows.Close()

	return s.scanSessions(rows)
}

// GetAllSessions retrieves all capture sessions
func (s *Storage) GetAllSessions() ([]*CaptureSession, error) {
	rows, err := s.db.Query(`
		SELECT id, name, extractor_pattern, extractor_location, extractor_name,
		       started_at, completed_at, paused_at, token_count, status,
		       target_count, timeout_seconds, stop_reason,
		       last_analyzed_at, last_analysis_count, analysis_interval
		FROM capture_sessions
		ORDER BY started_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("query all sessions: %w", err)
	}
	defer rows.Close()

	return s.scanSessions(rows)
}

// scanSessions is a helper to scan multiple session rows
func (s *Storage) scanSessions(rows *sql.Rows) ([]*CaptureSession, error) {
	var sessions []*CaptureSession

	for rows.Next() {
		var session CaptureSession
		var completedAt, pausedAt, lastAnalyzedAt sql.NullTime
		var stopReason sql.NullString
		var extractor TokenExtractor
		var timeoutSeconds int64

		err := rows.Scan(
			&session.ID, &session.Name,
			&extractor.Pattern, &extractor.Location, &extractor.Name,
			&session.StartedAt, &completedAt, &pausedAt, &session.TokenCount, &session.Status,
			&session.TargetCount, &timeoutSeconds, &stopReason,
			&lastAnalyzedAt, &session.LastAnalysisCount, &session.AnalysisInterval,
		)
		if err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}

		session.Extractor = extractor
		session.Timeout = time.Duration(timeoutSeconds) * time.Second

		if completedAt.Valid {
			session.CompletedAt = &completedAt.Time
		}
		if pausedAt.Valid {
			session.PausedAt = &pausedAt.Time
		}
		if lastAnalyzedAt.Valid {
			session.LastAnalyzedAt = &lastAnalyzedAt.Time
		}
		if stopReason.Valid {
			session.StopReason = StopReason(stopReason.String)
		}

		sessions = append(sessions, &session)
	}

	return sessions, nil
}

// CompleteSession marks a session as completed (deprecated, use StopSession instead)
func (s *Storage) CompleteSession(sessionID int64) error {
	return s.StopSession(sessionID, StopReasonManual)
}

// Close closes the database connection
func (s *Storage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
