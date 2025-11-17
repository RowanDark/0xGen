package main

import (
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
		token_count INTEGER DEFAULT 0,
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
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}

	return nil
}

// CreateSession creates a new capture session
func (s *Storage) CreateSession(name string, extractor TokenExtractor) (*CaptureSession, error) {
	now := time.Now().UTC()
	result, err := s.db.Exec(`
		INSERT INTO capture_sessions (name, extractor_pattern, extractor_location, extractor_name, started_at)
		VALUES (?, ?, ?, ?, ?)
	`, name, extractor.Pattern, extractor.Location, extractor.Name, now)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("get session id: %w", err)
	}

	return &CaptureSession{
		ID:        id,
		Name:      name,
		Extractor: extractor,
		StartedAt: now,
	}, nil
}

// StoreToken stores a captured token sample
func (s *Storage) StoreToken(sample TokenSample) error {
	_, err := s.db.Exec(`
		INSERT INTO token_samples (capture_session_id, token_value, token_length, captured_at, source_request_id)
		VALUES (?, ?, ?, ?, ?)
	`, sample.CaptureSessionID, sample.TokenValue, sample.TokenLength, sample.CapturedAt, sample.SourceRequestID)
	if err != nil {
		return fmt.Errorf("store token: %w", err)
	}

	// Update session token count
	_, err = s.db.Exec(`
		UPDATE capture_sessions
		SET token_count = token_count + 1
		WHERE id = ?
	`, sample.CaptureSessionID)
	if err != nil {
		return fmt.Errorf("update session count: %w", err)
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
	var completedAt sql.NullTime
	var extractor TokenExtractor

	err := s.db.QueryRow(`
		SELECT id, name, extractor_pattern, extractor_location, extractor_name,
		       started_at, completed_at, token_count
		FROM capture_sessions
		WHERE id = ?
	`, sessionID).Scan(
		&session.ID, &session.Name,
		&extractor.Pattern, &extractor.Location, &extractor.Name,
		&session.StartedAt, &completedAt, &session.TokenCount,
	)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}

	session.Extractor = extractor
	if completedAt.Valid {
		session.CompletedAt = &completedAt.Time
	}

	return &session, nil
}

// CompleteSession marks a session as completed
func (s *Storage) CompleteSession(sessionID int64) error {
	_, err := s.db.Exec(`
		UPDATE capture_sessions
		SET completed_at = ?
		WHERE id = ?
	`, time.Now().UTC(), sessionID)
	if err != nil {
		return fmt.Errorf("complete session: %w", err)
	}
	return nil
}

// Close closes the database connection
func (s *Storage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
