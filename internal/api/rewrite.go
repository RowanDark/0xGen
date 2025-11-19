package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/RowanDark/0xgen/internal/rewrite"
)

// AuthMiddleware is a function that wraps an HTTP handler with authentication
type AuthMiddleware func(http.Handler) http.Handler

// RewriteAPI handles HTTP endpoints for the Rewrite engine
type RewriteAPI struct {
	engine          *rewrite.Engine
	sandbox         *rewrite.Sandbox
	testCaseManager *rewrite.TestCaseManager
	logger          *slog.Logger
	authMiddleware  AuthMiddleware
}

// SetAuthMiddleware sets the authentication middleware for the API
func (api *RewriteAPI) SetAuthMiddleware(middleware AuthMiddleware) {
	api.authMiddleware = middleware
}

// NewRewriteAPI creates a new Rewrite API handler
func NewRewriteAPI(engine *rewrite.Engine, logger *slog.Logger) *RewriteAPI {
	sandbox := rewrite.NewSandbox(engine, logger)
	testCaseManager := rewrite.NewTestCaseManager(engine.GetStorage(), sandbox, logger)

	return &RewriteAPI{
		engine:          engine,
		sandbox:         sandbox,
		testCaseManager: testCaseManager,
		logger:          logger,
	}
}

// RegisterRoutes registers all Rewrite API routes with the provided mux
func (api *RewriteAPI) RegisterRoutes(mux *http.ServeMux) {
	// Helper to wrap handlers with authentication if middleware is set
	wrap := func(handler http.HandlerFunc) http.Handler {
		if api.authMiddleware != nil {
			return api.authMiddleware(handler)
		}
		return handler
	}

	// Rule management
	mux.Handle("/api/v1/rewrite/rules", wrap(api.handleRules))
	mux.Handle("/api/v1/rewrite/rules/", wrap(api.handleRuleByID))
	mux.Handle("/api/v1/rewrite/rules/import", wrap(api.handleImportRules))
	mux.Handle("/api/v1/rewrite/rules/export", wrap(api.handleExportRules))

	// Sandbox testing
	mux.Handle("/api/v1/rewrite/sandbox/test-request", wrap(api.handleTestRequest))
	mux.Handle("/api/v1/rewrite/sandbox/test-response", wrap(api.handleTestResponse))

	// Test cases
	mux.Handle("/api/v1/rewrite/test-cases", wrap(api.handleTestCases))
	mux.Handle("/api/v1/rewrite/test-cases/", wrap(api.handleTestCaseByID))
	mux.Handle("/api/v1/rewrite/test-cases/run", wrap(api.handleRunTestCase))
	mux.Handle("/api/v1/rewrite/test-cases/run-all", wrap(api.handleRunAllTestCases))

	// Metrics
	mux.Handle("/api/v1/rewrite/metrics", wrap(api.handleMetrics))
}

// handleRules handles GET (list) and POST (create) for rules
func (api *RewriteAPI) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		api.listRules(w, r)
	case http.MethodPost:
		api.createRule(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *RewriteAPI) listRules(w http.ResponseWriter, r *http.Request) {
	rules, err := api.engine.ListRules(r.Context())
	if err != nil {
		api.logger.Error("failed to list rules", "error", err)
		http.Error(w, fmt.Sprintf("Failed to list rules: %v", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": rules,
	})
}

func (api *RewriteAPI) createRule(w http.ResponseWriter, r *http.Request) {
	var rule rewrite.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := api.engine.CreateRule(r.Context(), &rule); err != nil {
		api.logger.Error("failed to create rule", "error", err)
		http.Error(w, fmt.Sprintf("Failed to create rule: %v", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"rule": rule,
	})
}

// handleRuleByID handles GET (retrieve), PUT (update), and DELETE for a specific rule
func (api *RewriteAPI) handleRuleByID(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path
	idStr := strings.TrimPrefix(r.URL.Path, "/api/v1/rewrite/rules/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid rule ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		api.getRule(w, r, id)
	case http.MethodPut:
		api.updateRule(w, r, id)
	case http.MethodDelete:
		api.deleteRule(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *RewriteAPI) getRule(w http.ResponseWriter, r *http.Request, id int) {
	rule, err := api.engine.GetRule(r.Context(), id)
	if err != nil {
		api.logger.Error("failed to get rule", "id", id, "error", err)
		http.Error(w, fmt.Sprintf("Failed to get rule: %v", err), http.StatusNotFound)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"rule": rule,
	})
}

func (api *RewriteAPI) updateRule(w http.ResponseWriter, r *http.Request, id int) {
	var rule rewrite.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	rule.ID = id
	if err := api.engine.UpdateRule(r.Context(), &rule); err != nil {
		api.logger.Error("failed to update rule", "id", id, "error", err)
		http.Error(w, fmt.Sprintf("Failed to update rule: %v", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"rule": rule,
	})
}

func (api *RewriteAPI) deleteRule(w http.ResponseWriter, r *http.Request, id int) {
	if err := api.engine.DeleteRule(r.Context(), id); err != nil {
		api.logger.Error("failed to delete rule", "id", id, "error", err)
		http.Error(w, fmt.Sprintf("Failed to delete rule: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleImportRules handles importing rules from JSON
func (api *RewriteAPI) handleImportRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Rules []*rewrite.Rule `json:"rules"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := api.engine.ImportRules(r.Context(), req.Rules); err != nil {
		api.logger.Error("failed to import rules", "error", err)
		http.Error(w, fmt.Sprintf("Failed to import rules: %v", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"imported": len(req.Rules),
	})
}

// handleExportRules handles exporting all rules to JSON
func (api *RewriteAPI) handleExportRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rules, err := api.engine.ExportRules(r.Context())
	if err != nil {
		api.logger.Error("failed to export rules", "error", err)
		http.Error(w, fmt.Sprintf("Failed to export rules: %v", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": rules,
	})
}

// handleTestRequest handles testing rules against a request in the sandbox
func (api *RewriteAPI) handleTestRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Input   *rewrite.TestRequestInput `json:"input"`
		RuleIDs []int                     `json:"rule_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	result, err := api.sandbox.TestRequest(r.Context(), req.Input, req.RuleIDs)
	if err != nil {
		api.logger.Error("failed to test request", "error", err)
		http.Error(w, fmt.Sprintf("Failed to test request: %v", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, http.StatusOK, result)
}

// handleTestResponse handles testing rules against a response in the sandbox
func (api *RewriteAPI) handleTestResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Input   *rewrite.TestResponseInput `json:"input"`
		RuleIDs []int                      `json:"rule_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	result, err := api.sandbox.TestResponse(r.Context(), req.Input, req.RuleIDs)
	if err != nil {
		api.logger.Error("failed to test response", "error", err)
		http.Error(w, fmt.Sprintf("Failed to test response: %v", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, http.StatusOK, result)
}

// handleTestCases handles GET (list) and POST (create) for test cases
func (api *RewriteAPI) handleTestCases(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		api.listTestCases(w, r)
	case http.MethodPost:
		api.createTestCase(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *RewriteAPI) listTestCases(w http.ResponseWriter, r *http.Request) {
	testCases, err := api.testCaseManager.ListTestCases(r.Context())
	if err != nil {
		api.logger.Error("failed to list test cases", "error", err)
		http.Error(w, fmt.Sprintf("Failed to list test cases: %v", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"test_cases": testCases,
	})
}

func (api *RewriteAPI) createTestCase(w http.ResponseWriter, r *http.Request) {
	var testCase rewrite.TestCase
	if err := json.NewDecoder(r.Body).Decode(&testCase); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := api.testCaseManager.CreateTestCase(r.Context(), &testCase); err != nil {
		api.logger.Error("failed to create test case", "error", err)
		http.Error(w, fmt.Sprintf("Failed to create test case: %v", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"test_case": testCase,
	})
}

// handleTestCaseByID handles GET and DELETE for a specific test case
func (api *RewriteAPI) handleTestCaseByID(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/v1/rewrite/test-cases/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid test case ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		api.getTestCase(w, r, id)
	case http.MethodDelete:
		api.deleteTestCase(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *RewriteAPI) getTestCase(w http.ResponseWriter, r *http.Request, id int) {
	testCase, err := api.testCaseManager.GetTestCase(r.Context(), id)
	if err != nil {
		api.logger.Error("failed to get test case", "id", id, "error", err)
		http.Error(w, fmt.Sprintf("Failed to get test case: %v", err), http.StatusNotFound)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"test_case": testCase,
	})
}

func (api *RewriteAPI) deleteTestCase(w http.ResponseWriter, r *http.Request, id int) {
	if err := api.testCaseManager.DeleteTestCase(r.Context(), id); err != nil {
		api.logger.Error("failed to delete test case", "id", id, "error", err)
		http.Error(w, fmt.Sprintf("Failed to delete test case: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleRunTestCase handles running a single test case
func (api *RewriteAPI) handleRunTestCase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID int `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	result, err := api.testCaseManager.RunTestCase(r.Context(), req.ID)
	if err != nil {
		api.logger.Error("failed to run test case", "id", req.ID, "error", err)
		http.Error(w, fmt.Sprintf("Failed to run test case: %v", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, http.StatusOK, result)
}

// handleRunAllTestCases handles running all test cases
func (api *RewriteAPI) handleRunAllTestCases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	results, err := api.testCaseManager.RunAllTestCases(r.Context())
	if err != nil {
		api.logger.Error("failed to run all test cases", "error", err)
		http.Error(w, fmt.Sprintf("Failed to run all test cases: %v", err), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"results": results,
	})
}

// handleMetrics handles retrieving performance metrics
func (api *RewriteAPI) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metrics := api.engine.GetMetrics()

	api.writeJSON(w, http.StatusOK, metrics)
}

// writeJSON writes a JSON response
func (api *RewriteAPI) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		api.logger.Error("failed to encode JSON response", "error", err)
	}
}
