package blitz

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // SQLite driver
)

// SQLiteStorage implements the Storage interface using SQLite.
type SQLiteStorage struct {
	db         *sql.DB
	sessionID  string
	insertStmt *sql.Stmt
}

// NewSQLiteStorage creates a new SQLite storage backend.
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
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

	storage := &SQLiteStorage{
		db: db,
	}

	if err := storage.createTables(); err != nil {
		db.Close()
		return nil, err
	}

	// Try to use existing session ID if database has data
	// Otherwise create a new session ID
	if err := storage.initializeSessionID(); err != nil {
		db.Close()
		return nil, err
	}

	// Prepare insert statement
	stmt, err := db.Prepare(`
		INSERT INTO results (
			session_id, request_id, position, position_name, payload, payload_set,
			status_code, duration_ms, content_length, request_method, request_url,
			request_headers, request_body, response_headers, response_body,
			matches, error, timestamp, anomaly_status_code, anomaly_content_len_delta,
			anomaly_response_time_factor, anomaly_pattern_count, is_interesting
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("prepare statement: %w", err)
	}
	storage.insertStmt = stmt

	return storage, nil
}

// createTables initializes the database schema.
func (s *SQLiteStorage) createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		request_id TEXT NOT NULL,
		position INTEGER NOT NULL,
		position_name TEXT,
		payload TEXT,
		payload_set TEXT, -- JSON map for multi-position attacks
		status_code INTEGER,
		duration_ms INTEGER,
		content_length INTEGER,
		request_method TEXT,
		request_url TEXT,
		request_headers TEXT, -- JSON
		request_body TEXT,
		response_headers TEXT, -- JSON
		response_body TEXT,
		matches TEXT, -- JSON array of pattern matches
		error TEXT,
		timestamp DATETIME NOT NULL,
		anomaly_status_code BOOLEAN,
		anomaly_content_len_delta INTEGER,
		anomaly_response_time_factor REAL,
		anomaly_pattern_count INTEGER,
		is_interesting BOOLEAN,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_session ON results(session_id);
	CREATE INDEX IF NOT EXISTS idx_status ON results(status_code);
	CREATE INDEX IF NOT EXISTS idx_interesting ON results(is_interesting);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON results(timestamp);
	CREATE INDEX IF NOT EXISTS idx_error ON results(error);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}

	return nil
}

// initializeSessionID sets the session ID by either using an existing one
// from the database or creating a new one if the database is empty.
func (s *SQLiteStorage) initializeSessionID() error {
	// Try to find the most recent session ID in the database
	var existingSessionID sql.NullString
	err := s.db.QueryRow(`
		SELECT session_id FROM results
		ORDER BY created_at DESC
		LIMIT 1
	`).Scan(&existingSessionID)

	if err == sql.ErrNoRows || !existingSessionID.Valid {
		// No existing data, create a new session ID
		s.sessionID = fmt.Sprintf("session_%d", time.Now().Unix())
		return nil
	}

	if err != nil {
		return fmt.Errorf("query existing session: %w", err)
	}

	// Use the existing session ID
	s.sessionID = existingSessionID.String
	return nil
}

// Store saves a fuzzing result to the database atomically.
func (s *SQLiteStorage) Store(result *FuzzResult) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() // Rollback if not committed

	// Serialize complex fields to JSON
	payloadSetJSON, _ := json.Marshal(result.PayloadSet)
	requestHeadersJSON, _ := json.Marshal(result.Request.Headers)
	responseHeadersJSON, _ := json.Marshal(result.Response.Headers)
	matchesJSON, _ := json.Marshal(result.Matches)

	// Anomaly fields
	var anomalyStatus sql.NullBool
	var anomalyContentDelta sql.NullInt64
	var anomalyTimeFactor sql.NullFloat64
	var anomalyPatternCount sql.NullInt64
	var isInteresting sql.NullBool

	if result.Anomaly != nil {
		anomalyStatus = sql.NullBool{Bool: result.Anomaly.StatusCodeAnomaly, Valid: true}
		anomalyContentDelta = sql.NullInt64{Int64: result.Anomaly.ContentLengthDelta, Valid: true}
		anomalyTimeFactor = sql.NullFloat64{Float64: result.Anomaly.ResponseTimeFactor, Valid: true}
		anomalyPatternCount = sql.NullInt64{Int64: int64(result.Anomaly.PatternAnomalies), Valid: true}
		isInteresting = sql.NullBool{Bool: result.Anomaly.IsInteresting, Valid: true}
	}

	// Use transaction-bound prepared statement
	txStmt := tx.Stmt(s.insertStmt)
	sqlResult, err := txStmt.Exec(
		s.sessionID,
		result.RequestID,
		result.Position,
		result.PositionName,
		result.Payload,
		string(payloadSetJSON),
		result.StatusCode,
		result.Duration,
		result.ContentLen,
		result.Request.Method,
		result.Request.URL,
		string(requestHeadersJSON),
		result.Request.Body,
		string(responseHeadersJSON),
		result.Response.Body,
		string(matchesJSON),
		result.Error,
		result.Timestamp,
		anomalyStatus,
		anomalyContentDelta,
		anomalyTimeFactor,
		anomalyPatternCount,
		isInteresting,
	)
	if err != nil {
		return fmt.Errorf("insert result: %w", err)
	}

	// Get the inserted ID
	id, err := sqlResult.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}
	result.ID = id

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// Query retrieves results matching the given filters.
func (s *SQLiteStorage) Query(filters QueryFilters) ([]*FuzzResult, error) {
	query := "SELECT * FROM results WHERE session_id = ?"
	args := []interface{}{s.sessionID}

	if len(filters.StatusCodes) > 0 {
		placeholders := ""
		for i, code := range filters.StatusCodes {
			if i > 0 {
				placeholders += ", "
			}
			placeholders += "?"
			args = append(args, code)
		}
		query += " AND status_code IN (" + placeholders + ")"
	}

	if filters.MinDuration > 0 {
		query += " AND duration_ms >= ?"
		args = append(args, filters.MinDuration)
	}

	if filters.MaxDuration > 0 {
		query += " AND duration_ms <= ?"
		args = append(args, filters.MaxDuration)
	}

	if filters.HasError != nil {
		if *filters.HasError {
			query += " AND error IS NOT NULL AND error != ''"
		} else {
			query += " AND (error IS NULL OR error = '')"
		}
	}

	if filters.HasAnomalies != nil && *filters.HasAnomalies {
		query += " AND is_interesting = 1"
	}

	query += " ORDER BY timestamp DESC"

	if filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filters.Limit)
	}

	if filters.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filters.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query results: %w", err)
	}
	defer rows.Close()

	var results []*FuzzResult

	for rows.Next() {
		result, err := s.scanResult(rows)
		if err != nil {
			return nil, fmt.Errorf("scan result: %w", err)
		}
		results = append(results, result)
	}

	return results, nil
}

// scanResult reads a result from a database row.
func (s *SQLiteStorage) scanResult(rows *sql.Rows) (*FuzzResult, error) {
	var result FuzzResult
	var payloadSetJSON, requestHeadersJSON, responseHeadersJSON, matchesJSON []byte
	var anomalyStatus, isInteresting sql.NullBool
	var anomalyContentDelta, anomalyPatternCount sql.NullInt64
	var anomalyTimeFactor sql.NullFloat64
	var errorStr sql.NullString
	var createdAt time.Time
	var sessionID string

	err := rows.Scan(
		&result.ID,
		&sessionID,
		&result.RequestID,
		&result.Position,
		&result.PositionName,
		&result.Payload,
		&payloadSetJSON,
		&result.StatusCode,
		&result.Duration,
		&result.ContentLen,
		&result.Request.Method,
		&result.Request.URL,
		&requestHeadersJSON,
		&result.Request.Body,
		&responseHeadersJSON,
		&result.Response.Body,
		&matchesJSON,
		&errorStr,
		&result.Timestamp,
		&anomalyStatus,
		&anomalyContentDelta,
		&anomalyTimeFactor,
		&anomalyPatternCount,
		&isInteresting,
		&createdAt,
	)
	if err != nil {
		return nil, err
	}

	// Deserialize JSON fields
	if len(payloadSetJSON) > 0 {
		json.Unmarshal(payloadSetJSON, &result.PayloadSet)
	}
	if len(requestHeadersJSON) > 0 {
		json.Unmarshal(requestHeadersJSON, &result.Request.Headers)
	}
	if len(responseHeadersJSON) > 0 {
		json.Unmarshal(responseHeadersJSON, &result.Response.Headers)
	}
	if len(matchesJSON) > 0 {
		json.Unmarshal(matchesJSON, &result.Matches)
	}

	if errorStr.Valid {
		result.Error = errorStr.String
	}

	// Reconstruct anomaly indicator
	if isInteresting.Valid && isInteresting.Bool {
		result.Anomaly = &AnomalyIndicator{
			StatusCodeAnomaly:  anomalyStatus.Bool,
			ContentLengthDelta: anomalyContentDelta.Int64,
			ResponseTimeFactor: anomalyTimeFactor.Float64,
			PatternAnomalies:   int(anomalyPatternCount.Int64),
			IsInteresting:      true,
		}
	}

	return &result, nil
}

// GetStats returns summary statistics for the current session.
func (s *SQLiteStorage) GetStats() (*Stats, error) {
	stats := &Stats{
		UniqueStatuses: make(map[int]int64),
	}

	// Total requests
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM results WHERE session_id = ?
	`, s.sessionID).Scan(&stats.TotalRequests)
	if err != nil {
		return nil, fmt.Errorf("count total: %w", err)
	}

	// Successful vs failed
	err = s.db.QueryRow(`
		SELECT
			COUNT(CASE WHEN error IS NULL OR error = '' THEN 1 END) as success,
			COUNT(CASE WHEN error IS NOT NULL AND error != '' THEN 1 END) as failed
		FROM results WHERE session_id = ?
	`, s.sessionID).Scan(&stats.SuccessfulReqs, &stats.FailedReqs)
	if err != nil {
		return nil, fmt.Errorf("count success/failed: %w", err)
	}

	// Status code distribution
	rows, err := s.db.Query(`
		SELECT status_code, COUNT(*) as count
		FROM results
		WHERE session_id = ?
		GROUP BY status_code
	`, s.sessionID)
	if err != nil {
		return nil, fmt.Errorf("query status codes: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var code int
		var count int64
		if err := rows.Scan(&code, &count); err != nil {
			return nil, err
		}
		stats.UniqueStatuses[code] = count
	}

	// Duration statistics
	err = s.db.QueryRow(`
		SELECT
			AVG(duration_ms),
			MIN(duration_ms),
			MAX(duration_ms)
		FROM results
		WHERE session_id = ? AND (error IS NULL OR error = '')
	`, s.sessionID).Scan(&stats.AvgDuration, &stats.MinDuration, &stats.MaxDuration)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("duration stats: %w", err)
	}

	// Anomaly count
	err = s.db.QueryRow(`
		SELECT COUNT(*) FROM results
		WHERE session_id = ? AND is_interesting = 1
	`, s.sessionID).Scan(&stats.AnomalyCount)
	if err != nil {
		return nil, fmt.Errorf("anomaly count: %w", err)
	}

	// Pattern match count
	err = s.db.QueryRow(`
		SELECT COUNT(*) FROM results
		WHERE session_id = ? AND matches IS NOT NULL AND matches != '[]'
	`, s.sessionID).Scan(&stats.PatternMatchCount)
	if err != nil {
		return nil, fmt.Errorf("pattern match count: %w", err)
	}

	return stats, nil
}

// Close releases database resources.
func (s *SQLiteStorage) Close() error {
	if s.insertStmt != nil {
		s.insertStmt.Close()
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetSessionID returns the current session identifier.
func (s *SQLiteStorage) GetSessionID() string {
	return s.sessionID
}

// SetSessionID sets a custom session identifier.
func (s *SQLiteStorage) SetSessionID(id string) {
	s.sessionID = id
}
