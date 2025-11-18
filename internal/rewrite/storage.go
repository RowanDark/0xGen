package rewrite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite" // SQLite driver
)

// Storage handles persistent storage of rewrite rules.
type Storage struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewStorage creates a new storage instance.
func NewStorage(dbPath string, logger *slog.Logger) (*Storage, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Open database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	storage := &Storage{
		db:     db,
		logger: logger,
	}

	// Create tables
	if err := storage.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	// Create test case tables
	if err := storage.InitTestCaseTables(); err != nil {
		return nil, fmt.Errorf("failed to create test case tables: %w", err)
	}

	return storage, nil
}

// Close closes the database connection.
func (s *Storage) Close() error {
	return s.db.Close()
}

// createTables creates the necessary database tables.
func (s *Storage) createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		description TEXT,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		priority INTEGER NOT NULL DEFAULT 0,

		-- Scope (JSON)
		scope_direction TEXT NOT NULL,
		scope_methods TEXT, -- JSON array
		scope_url_pattern TEXT,
		scope_content_type TEXT,

		-- Conditions and Actions (JSON)
		conditions TEXT, -- JSON array
		actions TEXT NOT NULL, -- JSON array

		-- Metadata
		created_at TIMESTAMP NOT NULL,
		modified_at TIMESTAMP NOT NULL,
		author TEXT,
		tags TEXT, -- JSON array
		version INTEGER NOT NULL DEFAULT 1,

		CONSTRAINT name_unique UNIQUE(name)
	);

	CREATE INDEX IF NOT EXISTS idx_enabled ON rules(enabled);
	CREATE INDEX IF NOT EXISTS idx_priority ON rules(priority DESC);
	CREATE INDEX IF NOT EXISTS idx_direction ON rules(scope_direction);
	CREATE INDEX IF NOT EXISTS idx_created ON rules(created_at);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// CreateRule creates a new rule.
func (s *Storage) CreateRule(ctx context.Context, rule *Rule) error {
	// Marshal JSON fields
	scopeMethods, err := json.Marshal(rule.Scope.Methods)
	if err != nil {
		return fmt.Errorf("failed to marshal scope methods: %w", err)
	}

	conditions, err := json.Marshal(rule.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	actions, err := json.Marshal(rule.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	tags, err := json.Marshal(rule.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	query := `
	INSERT INTO rules (
		name, description, enabled, priority,
		scope_direction, scope_methods, scope_url_pattern, scope_content_type,
		conditions, actions,
		created_at, modified_at, author, tags, version
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := s.db.ExecContext(ctx, query,
		rule.Name,
		rule.Description,
		rule.Enabled,
		rule.Priority,
		rule.Scope.Direction.String(),
		string(scopeMethods),
		rule.Scope.URLPattern,
		rule.Scope.ContentType,
		string(conditions),
		string(actions),
		rule.CreatedAt,
		rule.ModifiedAt,
		rule.Author,
		string(tags),
		rule.Version,
	)
	if err != nil {
		return fmt.Errorf("failed to insert rule: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get insert ID: %w", err)
	}

	rule.ID = int(id)
	return nil
}

// UpdateRule updates an existing rule.
func (s *Storage) UpdateRule(ctx context.Context, rule *Rule) error {
	// Marshal JSON fields
	scopeMethods, err := json.Marshal(rule.Scope.Methods)
	if err != nil {
		return fmt.Errorf("failed to marshal scope methods: %w", err)
	}

	conditions, err := json.Marshal(rule.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	actions, err := json.Marshal(rule.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	tags, err := json.Marshal(rule.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	query := `
	UPDATE rules SET
		name = ?,
		description = ?,
		enabled = ?,
		priority = ?,
		scope_direction = ?,
		scope_methods = ?,
		scope_url_pattern = ?,
		scope_content_type = ?,
		conditions = ?,
		actions = ?,
		modified_at = ?,
		author = ?,
		tags = ?,
		version = ?
	WHERE id = ?
	`

	result, err := s.db.ExecContext(ctx, query,
		rule.Name,
		rule.Description,
		rule.Enabled,
		rule.Priority,
		rule.Scope.Direction.String(),
		string(scopeMethods),
		rule.Scope.URLPattern,
		rule.Scope.ContentType,
		string(conditions),
		string(actions),
		rule.ModifiedAt,
		rule.Author,
		string(tags),
		rule.Version,
		rule.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("rule not found: %d", rule.ID)
	}

	return nil
}

// DeleteRule deletes a rule by ID.
func (s *Storage) DeleteRule(ctx context.Context, id int) error {
	query := `DELETE FROM rules WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("rule not found: %d", id)
	}

	return nil
}

// GetRule retrieves a rule by ID.
func (s *Storage) GetRule(ctx context.Context, id int) (*Rule, error) {
	query := `
	SELECT
		id, name, description, enabled, priority,
		scope_direction, scope_methods, scope_url_pattern, scope_content_type,
		conditions, actions,
		created_at, modified_at, author, tags, version
	FROM rules
	WHERE id = ?
	`

	var rule Rule
	var scopeDirection string
	var scopeMethods, conditions, actions, tags sql.NullString
	var createdAt, modifiedAt int64

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&rule.ID,
		&rule.Name,
		&rule.Description,
		&rule.Enabled,
		&rule.Priority,
		&scopeDirection,
		&scopeMethods,
		&rule.Scope.URLPattern,
		&rule.Scope.ContentType,
		&conditions,
		&actions,
		&createdAt,
		&modifiedAt,
		&rule.Author,
		&tags,
		&rule.Version,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("rule not found: %d", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query rule: %w", err)
	}

	// Parse direction
	switch scopeDirection {
	case "request":
		rule.Scope.Direction = DirectionRequest
	case "response":
		rule.Scope.Direction = DirectionResponse
	case "both":
		rule.Scope.Direction = DirectionBoth
	}

	// Parse JSON fields
	if scopeMethods.Valid && scopeMethods.String != "" {
		if err := json.Unmarshal([]byte(scopeMethods.String), &rule.Scope.Methods); err != nil {
			return nil, fmt.Errorf("failed to unmarshal scope methods: %w", err)
		}
	}

	if conditions.Valid && conditions.String != "" {
		if err := json.Unmarshal([]byte(conditions.String), &rule.Conditions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal conditions: %w", err)
		}
	}

	if actions.Valid && actions.String != "" {
		if err := json.Unmarshal([]byte(actions.String), &rule.Actions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal actions: %w", err)
		}
	}

	if tags.Valid && tags.String != "" {
		if err := json.Unmarshal([]byte(tags.String), &rule.Tags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
		}
	}

	// Convert timestamps
	rule.CreatedAt = time.Unix(createdAt, 0)
	rule.ModifiedAt = time.Unix(modifiedAt, 0)

	// Validate to compile regexes
	if err := rule.Validate(); err != nil {
		s.logger.Warn("loaded rule has validation errors", "id", rule.ID, "error", err)
	}

	return &rule, nil
}

// ListRules returns all rules.
func (s *Storage) ListRules() ([]*Rule, error) {
	query := `
	SELECT
		id, name, description, enabled, priority,
		scope_direction, scope_methods, scope_url_pattern, scope_content_type,
		conditions, actions,
		created_at, modified_at, author, tags, version
	FROM rules
	ORDER BY priority DESC, created_at ASC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	var rules []*Rule
	for rows.Next() {
		var rule Rule
		var scopeDirection string
		var scopeMethods, conditions, actions, tags sql.NullString
		var createdAt, modifiedAt int64

		err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&rule.Description,
			&rule.Enabled,
			&rule.Priority,
			&scopeDirection,
			&scopeMethods,
			&rule.Scope.URLPattern,
			&rule.Scope.ContentType,
			&conditions,
			&actions,
			&createdAt,
			&modifiedAt,
			&rule.Author,
			&tags,
			&rule.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rule: %w", err)
		}

		// Parse direction
		switch scopeDirection {
		case "request":
			rule.Scope.Direction = DirectionRequest
		case "response":
			rule.Scope.Direction = DirectionResponse
		case "both":
			rule.Scope.Direction = DirectionBoth
		}

		// Parse JSON fields
		if scopeMethods.Valid && scopeMethods.String != "" {
			if err := json.Unmarshal([]byte(scopeMethods.String), &rule.Scope.Methods); err != nil {
				s.logger.Warn("failed to unmarshal scope methods", "id", rule.ID, "error", err)
			}
		}

		if conditions.Valid && conditions.String != "" {
			if err := json.Unmarshal([]byte(conditions.String), &rule.Conditions); err != nil {
				s.logger.Warn("failed to unmarshal conditions", "id", rule.ID, "error", err)
			}
		}

		if actions.Valid && actions.String != "" {
			if err := json.Unmarshal([]byte(actions.String), &rule.Actions); err != nil {
				s.logger.Warn("failed to unmarshal actions", "id", rule.ID, "error", err)
			}
		}

		if tags.Valid && tags.String != "" {
			if err := json.Unmarshal([]byte(tags.String), &rule.Tags); err != nil {
				s.logger.Warn("failed to unmarshal tags", "id", rule.ID, "error", err)
			}
		}

		// Convert timestamps
		rule.CreatedAt = time.Unix(createdAt, 0)
		rule.ModifiedAt = time.Unix(modifiedAt, 0)

		// Validate to compile regexes
		if err := rule.Validate(); err != nil {
			s.logger.Warn("loaded rule has validation errors", "id", rule.ID, "error", err)
		}

		rules = append(rules, &rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rules: %w", err)
	}

	return rules, nil
}

// SearchRules searches for rules by name or tag.
func (s *Storage) SearchRules(ctx context.Context, query string) ([]*Rule, error) {
	sqlQuery := `
	SELECT
		id, name, description, enabled, priority,
		scope_direction, scope_methods, scope_url_pattern, scope_content_type,
		conditions, actions,
		created_at, modified_at, author, tags, version
	FROM rules
	WHERE name LIKE ? OR description LIKE ? OR tags LIKE ?
	ORDER BY priority DESC, created_at ASC
	`

	pattern := "%" + query + "%"
	rows, err := s.db.QueryContext(ctx, sqlQuery, pattern, pattern, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to search rules: %w", err)
	}
	defer rows.Close()

	var rules []*Rule
	for rows.Next() {
		var rule Rule
		var scopeDirection string
		var scopeMethods, conditions, actions, tags sql.NullString
		var createdAt, modifiedAt int64

		err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&rule.Description,
			&rule.Enabled,
			&rule.Priority,
			&scopeDirection,
			&scopeMethods,
			&rule.Scope.URLPattern,
			&rule.Scope.ContentType,
			&conditions,
			&actions,
			&createdAt,
			&modifiedAt,
			&rule.Author,
			&tags,
			&rule.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rule: %w", err)
		}

		// Parse direction
		switch scopeDirection {
		case "request":
			rule.Scope.Direction = DirectionRequest
		case "response":
			rule.Scope.Direction = DirectionResponse
		case "both":
			rule.Scope.Direction = DirectionBoth
		}

		// Parse JSON fields (same as ListRules)
		if scopeMethods.Valid && scopeMethods.String != "" {
			json.Unmarshal([]byte(scopeMethods.String), &rule.Scope.Methods)
		}
		if conditions.Valid && conditions.String != "" {
			json.Unmarshal([]byte(conditions.String), &rule.Conditions)
		}
		if actions.Valid && actions.String != "" {
			json.Unmarshal([]byte(actions.String), &rule.Actions)
		}
		if tags.Valid && tags.String != "" {
			json.Unmarshal([]byte(tags.String), &rule.Tags)
		}

		rule.CreatedAt = time.Unix(createdAt, 0)
		rule.ModifiedAt = time.Unix(modifiedAt, 0)

		rule.Validate()

		rules = append(rules, &rule)
	}

	return rules, nil
}
