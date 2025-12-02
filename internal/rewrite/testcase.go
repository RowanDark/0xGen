package rewrite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// TestCase represents a saved test case for rule testing.
type TestCase struct {
	ID             int                `json:"id"`
	Name           string             `json:"name"`
	Description    string             `json:"description"`
	Type           TestCaseType       `json:"type"` // "request" or "response"
	Input          interface{}        `json:"input"` // TestRequestInput or TestResponseInput
	ExpectedOutput interface{}        `json:"expected_output,omitempty"`
	RuleIDs        []int              `json:"rule_ids"` // Rules to test
	CreatedAt      time.Time          `json:"created_at"`
	ModifiedAt     time.Time          `json:"modified_at"`
	Tags           []string           `json:"tags,omitempty"`
}

// TestCaseType specifies whether the test case is for a request or response.
type TestCaseType string

const (
	TestCaseTypeRequest  TestCaseType = "request"
	TestCaseTypeResponse TestCaseType = "response"
)

// TestCaseResult represents the result of running a test case.
type TestCaseResult struct {
	TestCaseID    int               `json:"test_case_id"`
	TestCaseName  string            `json:"test_case_name"`
	Passed        bool              `json:"passed"`
	SandboxResult *SandboxResult    `json:"sandbox_result"`
	Failures      []string          `json:"failures,omitempty"`
	Duration      time.Duration     `json:"duration"`
	Timestamp     time.Time         `json:"timestamp"`
}

// TestSuite represents a collection of test cases.
type TestSuite struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	TestCaseIDs []int     `json:"test_case_ids"`
	CreatedAt   time.Time `json:"created_at"`
	ModifiedAt  time.Time `json:"modified_at"`
}

// TestSuiteResult represents the results of running a test suite.
type TestSuiteResult struct {
	TestSuiteID   int                `json:"test_suite_id"`
	TestSuiteName string             `json:"test_suite_name"`
	TotalTests    int                `json:"total_tests"`
	Passed        int                `json:"passed"`
	Failed        int                `json:"failed"`
	Results       []TestCaseResult   `json:"results"`
	Duration      time.Duration      `json:"duration"`
	Timestamp     time.Time          `json:"timestamp"`
}

// TestCaseManager handles test case storage and execution.
type TestCaseManager struct {
	storage *Storage
	sandbox *Sandbox
	logger  *slog.Logger
}

// NewTestCaseManager creates a new test case manager.
func NewTestCaseManager(storage *Storage, sandbox *Sandbox, logger *slog.Logger) *TestCaseManager {
	if logger == nil {
		logger = slog.Default()
	}

	return &TestCaseManager{
		storage: storage,
		sandbox: sandbox,
		logger:  logger,
	}
}

// CreateTestCase saves a new test case.
func (m *TestCaseManager) CreateTestCase(ctx context.Context, tc *TestCase) error {
	tc.CreatedAt = time.Now()
	tc.ModifiedAt = time.Now()

	// Serialize input and expected output
	inputJSON, err := json.Marshal(tc.Input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	var expectedOutputJSON []byte
	if tc.ExpectedOutput != nil {
		expectedOutputJSON, err = json.Marshal(tc.ExpectedOutput)
		if err != nil {
			return fmt.Errorf("failed to marshal expected output: %w", err)
		}
	}

	ruleIDsJSON, err := json.Marshal(tc.RuleIDs)
	if err != nil {
		return fmt.Errorf("failed to marshal rule IDs: %w", err)
	}

	tagsJSON, err := json.Marshal(tc.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	query := `
	INSERT INTO test_cases (
		name, description, type, input, expected_output, rule_ids,
		created_at, modified_at, tags
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := m.storage.db.ExecContext(ctx, query,
		tc.Name,
		tc.Description,
		string(tc.Type),
		string(inputJSON),
		string(expectedOutputJSON),
		string(ruleIDsJSON),
		tc.CreatedAt.Unix(),
		tc.ModifiedAt.Unix(),
		string(tagsJSON),
	)
	if err != nil {
		return fmt.Errorf("failed to insert test case: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get insert ID: %w", err)
	}

	tc.ID = int(id)
	return nil
}

// GetTestCase retrieves a test case by ID.
func (m *TestCaseManager) GetTestCase(ctx context.Context, id int) (*TestCase, error) {
	query := `
	SELECT id, name, description, type, input, expected_output, rule_ids,
		created_at, modified_at, tags
	FROM test_cases
	WHERE id = ?
	`

	var tc TestCase
	var tcType string
	var inputJSON, expectedOutputJSON, ruleIDsJSON, tagsJSON sql.NullString
	var createdAt, modifiedAt int64

	err := m.storage.db.QueryRowContext(ctx, query, id).Scan(
		&tc.ID,
		&tc.Name,
		&tc.Description,
		&tcType,
		&inputJSON,
		&expectedOutputJSON,
		&ruleIDsJSON,
		&createdAt,
		&modifiedAt,
		&tagsJSON,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("test case not found: %d", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query test case: %w", err)
	}

	tc.Type = TestCaseType(tcType)
	tc.CreatedAt = time.Unix(createdAt, 0)
	tc.ModifiedAt = time.Unix(modifiedAt, 0)

	// Deserialize input
	if inputJSON.Valid && inputJSON.String != "" {
		if tc.Type == TestCaseTypeRequest {
			var input TestRequestInput
			if err := json.Unmarshal([]byte(inputJSON.String), &input); err != nil {
				return nil, fmt.Errorf("failed to unmarshal input: %w", err)
			}
			tc.Input = &input
		} else {
			var input TestResponseInput
			if err := json.Unmarshal([]byte(inputJSON.String), &input); err != nil {
				return nil, fmt.Errorf("failed to unmarshal input: %w", err)
			}
			tc.Input = &input
		}
	}

	// Deserialize expected output
	if expectedOutputJSON.Valid && expectedOutputJSON.String != "" {
		if tc.Type == TestCaseTypeRequest {
			var output TestRequestInput
			if err := json.Unmarshal([]byte(expectedOutputJSON.String), &output); err != nil {
				return nil, fmt.Errorf("failed to unmarshal expected output: %w", err)
			}
			tc.ExpectedOutput = &output
		} else {
			var output TestResponseInput
			if err := json.Unmarshal([]byte(expectedOutputJSON.String), &output); err != nil {
				return nil, fmt.Errorf("failed to unmarshal expected output: %w", err)
			}
			tc.ExpectedOutput = &output
		}
	}

	// Deserialize rule IDs
	if ruleIDsJSON.Valid && ruleIDsJSON.String != "" {
		if err := json.Unmarshal([]byte(ruleIDsJSON.String), &tc.RuleIDs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rule IDs: %w", err)
		}
	}

	// Deserialize tags
	if tagsJSON.Valid && tagsJSON.String != "" {
		if err := json.Unmarshal([]byte(tagsJSON.String), &tc.Tags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
		}
	}

	return &tc, nil
}

// ListTestCases returns all test cases.
func (m *TestCaseManager) ListTestCases(ctx context.Context) ([]*TestCase, error) {
	query := `
	SELECT id, name, description, type, input, expected_output, rule_ids,
		created_at, modified_at, tags
	FROM test_cases
	ORDER BY created_at DESC
	`

	rows, err := m.storage.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query test cases: %w", err)
	}
	defer rows.Close()

	testCases := make([]*TestCase, 0)
	for rows.Next() {
		var tc TestCase
		var tcType string
		var inputJSON, expectedOutputJSON, ruleIDsJSON, tagsJSON sql.NullString
		var createdAt, modifiedAt int64

		err := rows.Scan(
			&tc.ID,
			&tc.Name,
			&tc.Description,
			&tcType,
			&inputJSON,
			&expectedOutputJSON,
			&ruleIDsJSON,
			&createdAt,
			&modifiedAt,
			&tagsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan test case: %w", err)
		}

		tc.Type = TestCaseType(tcType)
		tc.CreatedAt = time.Unix(createdAt, 0)
		tc.ModifiedAt = time.Unix(modifiedAt, 0)

		// Deserialize (simplified - same as GetTestCase)
		if inputJSON.Valid && inputJSON.String != "" {
			if tc.Type == TestCaseTypeRequest {
				var input TestRequestInput
				if err := json.Unmarshal([]byte(inputJSON.String), &input); err != nil {
					return nil, fmt.Errorf("unmarshal test case %d input: %w", tc.ID, err)
				}
				tc.Input = &input
			} else {
				var input TestResponseInput
				if err := json.Unmarshal([]byte(inputJSON.String), &input); err != nil {
					return nil, fmt.Errorf("unmarshal test case %d input: %w", tc.ID, err)
				}
				tc.Input = &input
			}
		}

		if ruleIDsJSON.Valid {
			if err := json.Unmarshal([]byte(ruleIDsJSON.String), &tc.RuleIDs); err != nil {
				return nil, fmt.Errorf("unmarshal test case %d rule IDs: %w", tc.ID, err)
			}
		}

		if tagsJSON.Valid {
			if err := json.Unmarshal([]byte(tagsJSON.String), &tc.Tags); err != nil {
				return nil, fmt.Errorf("unmarshal test case %d tags: %w", tc.ID, err)
			}
		}

		testCases = append(testCases, &tc)
	}

	return testCases, nil
}

// DeleteTestCase deletes a test case.
func (m *TestCaseManager) DeleteTestCase(ctx context.Context, id int) error {
	query := `DELETE FROM test_cases WHERE id = ?`
	result, err := m.storage.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete test case: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("test case not found: %d", id)
	}

	return nil
}

// RunTestCase executes a test case and returns the result.
func (m *TestCaseManager) RunTestCase(ctx context.Context, id int) (*TestCaseResult, error) {
	start := time.Now()

	tc, err := m.GetTestCase(ctx, id)
	if err != nil {
		return nil, err
	}

	result := &TestCaseResult{
		TestCaseID:   tc.ID,
		TestCaseName: tc.Name,
		Failures:     make([]string, 0),
		Timestamp:    time.Now(),
	}

	// Run in sandbox
	var sandboxResult *SandboxResult
	if tc.Type == TestCaseTypeRequest {
		input, ok := tc.Input.(*TestRequestInput)
		if !ok {
			return nil, fmt.Errorf("invalid request input type")
		}
		sandboxResult, err = m.sandbox.TestRequest(ctx, input, tc.RuleIDs)
	} else {
		input, ok := tc.Input.(*TestResponseInput)
		if !ok {
			return nil, fmt.Errorf("invalid response input type")
		}
		sandboxResult, err = m.sandbox.TestResponse(ctx, input, tc.RuleIDs)
	}

	if err != nil {
		result.Failures = append(result.Failures, fmt.Sprintf("Sandbox execution failed: %v", err))
		result.Passed = false
		result.Duration = time.Since(start)
		return result, nil
	}

	result.SandboxResult = sandboxResult

	// Compare with expected output if provided
	if tc.ExpectedOutput != nil {
		failures := m.compareOutputs(sandboxResult.ModifiedInput, tc.ExpectedOutput)
		result.Failures = append(result.Failures, failures...)
	}

	result.Passed = len(result.Failures) == 0
	result.Duration = time.Since(start)

	return result, nil
}

// RunAllTestCases runs all test cases and returns results.
func (m *TestCaseManager) RunAllTestCases(ctx context.Context) ([]TestCaseResult, error) {
	testCases, err := m.ListTestCases(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]TestCaseResult, 0, len(testCases))
	for _, tc := range testCases {
		result, err := m.RunTestCase(ctx, tc.ID)
		if err != nil {
			m.logger.Warn("failed to run test case", "id", tc.ID, "error", err)
			continue
		}
		results = append(results, *result)
	}

	return results, nil
}

// compareOutputs compares actual output with expected output.
func (m *TestCaseManager) compareOutputs(actual, expected interface{}) []string {
	failures := make([]string, 0)

	// Simple JSON comparison
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		failures = append(failures, fmt.Sprintf("Failed to marshal actual output: %v", err))
		return failures
	}

	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		failures = append(failures, fmt.Sprintf("Failed to marshal expected output: %v", err))
		return failures
	}

	// Normalize and compare
	var actualMap, expectedMap map[string]interface{}
	if err := json.Unmarshal(actualJSON, &actualMap); err != nil {
		failures = append(failures, fmt.Sprintf("Failed to unmarshal actual output: %v", err))
		return failures
	}
	if err := json.Unmarshal(expectedJSON, &expectedMap); err != nil {
		failures = append(failures, fmt.Sprintf("Failed to unmarshal expected output: %v", err))
		return failures
	}

	// Compare specific fields
	if actualMap["method"] != expectedMap["method"] {
		failures = append(failures, fmt.Sprintf("Method mismatch: got %v, want %v",
			actualMap["method"], expectedMap["method"]))
	}

	if actualMap["url"] != expectedMap["url"] {
		failures = append(failures, fmt.Sprintf("URL mismatch: got %v, want %v",
			actualMap["url"], expectedMap["url"]))
	}

	// Compare headers (basic)
	actualHeaders, _ := actualMap["headers"].(map[string]interface{})
	expectedHeaders, _ := expectedMap["headers"].(map[string]interface{})
	for key, expectedValue := range expectedHeaders {
		if actualValue, ok := actualHeaders[key]; !ok {
			failures = append(failures, fmt.Sprintf("Missing header: %s", key))
		} else if actualValue != expectedValue {
			failures = append(failures, fmt.Sprintf("Header %s mismatch: got %v, want %v",
				key, actualValue, expectedValue))
		}
	}

	// Compare body
	if actualMap["body"] != expectedMap["body"] {
		failures = append(failures, "Body mismatch")
	}

	return failures
}

// InitTestCaseTables creates the necessary database tables for test cases.
func (s *Storage) InitTestCaseTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS test_cases (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		type TEXT NOT NULL, -- 'request' or 'response'
		input TEXT NOT NULL, -- JSON
		expected_output TEXT, -- JSON
		rule_ids TEXT NOT NULL, -- JSON array
		created_at TIMESTAMP NOT NULL,
		modified_at TIMESTAMP NOT NULL,
		tags TEXT -- JSON array
	);

	CREATE INDEX IF NOT EXISTS idx_test_cases_type ON test_cases(type);
	CREATE INDEX IF NOT EXISTS idx_test_cases_created ON test_cases(created_at);

	CREATE TABLE IF NOT EXISTS test_suites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		test_case_ids TEXT NOT NULL, -- JSON array
		created_at TIMESTAMP NOT NULL,
		modified_at TIMESTAMP NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_test_suites_created ON test_suites(created_at);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create test case tables: %w", err)
	}

	return nil
}
