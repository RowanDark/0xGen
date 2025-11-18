package rewrite

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Engine is the main rewrite engine that orchestrates rule matching and execution.
type Engine struct {
	storage   *Storage
	variables *VariableStore
	matcher   *Matcher
	executor  *Executor
	logger    *slog.Logger

	// Rule cache
	mu          sync.RWMutex
	rulesCache  []*Rule
	cacheLoaded bool

	// Performance metrics
	metrics *EngineMetrics
}

// EngineMetrics tracks performance statistics.
type EngineMetrics struct {
	mu                sync.RWMutex
	totalRequests     int64
	totalResponses    int64
	rulesApplied      int64
	totalLatency      time.Duration
	slowRules         map[int]time.Duration // ruleID -> avg latency
	ruleExecutions    map[int]int64         // ruleID -> count
	ruleLatencies     map[int]time.Duration // ruleID -> total latency
}

// Config holds engine configuration.
type Config struct {
	DatabasePath string
	Logger       *slog.Logger
}

// NewEngine creates a new rewrite engine.
func NewEngine(config Config) (*Engine, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Initialize storage
	storage, err := NewStorage(config.DatabasePath, config.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize components
	variables := NewVariableStore()
	matcher := NewMatcher(variables)
	executor := NewExecutor(variables, config.Logger)

	engine := &Engine{
		storage:   storage,
		variables: variables,
		matcher:   matcher,
		executor:  executor,
		logger:    config.Logger,
		metrics: &EngineMetrics{
			slowRules:      make(map[int]time.Duration),
			ruleExecutions: make(map[int]int64),
			ruleLatencies:  make(map[int]time.Duration),
		},
	}

	// Load rules into cache
	if err := engine.loadRulesCache(); err != nil {
		config.Logger.Warn("failed to load rules cache", "error", err)
	}

	return engine, nil
}

// Close shuts down the engine and closes resources.
func (e *Engine) Close() error {
	if e.storage != nil {
		return e.storage.Close()
	}
	return nil
}

// loadRulesCache loads all enabled rules into memory.
func (e *Engine) loadRulesCache() error {
	rules, err := e.storage.ListRules()
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.rulesCache = rules
	e.cacheLoaded = true
	e.mu.Unlock()

	e.logger.Info("loaded rules cache", "count", len(rules))
	return nil
}

// RefreshCache reloads the rules cache.
func (e *Engine) RefreshCache() error {
	return e.loadRulesCache()
}

// ProcessRequest processes an HTTP request through the rewrite engine.
func (e *Engine) ProcessRequest(req *http.Request) (*http.Request, error) {
	start := time.Now()
	defer func() {
		e.metrics.mu.Lock()
		e.metrics.totalRequests++
		e.metrics.totalLatency += time.Since(start)
		e.metrics.mu.Unlock()
	}()

	// Generate request ID for variable scoping
	requestID := uuid.New().String()
	defer e.variables.ClearRequest(requestID)

	// Get active rules for requests
	rules := e.GetActiveRules(DirectionRequest)

	// Apply each matching rule
	for _, rule := range rules {
		if e.matcher.MatchesScope(rule, req, false) {
			// Evaluate conditions
			if e.matcher.EvaluateConditions(rule, req, 0, nil, nil, requestID) {
				ruleStart := time.Now()

				// Execute actions
				if err := e.executor.ExecuteRequestActions(rule, req, requestID); err != nil {
					e.logger.Warn("failed to execute rule actions",
						"rule", rule.Name,
						"error", err,
					)
				} else {
					e.trackRuleExecution(rule.ID, time.Since(ruleStart))
				}
			}
		}
	}

	return req, nil
}

// ProcessResponse processes an HTTP response through the rewrite engine.
func (e *Engine) ProcessResponse(resp *http.Response) (*http.Response, error) {
	start := time.Now()
	defer func() {
		e.metrics.mu.Lock()
		e.metrics.totalResponses++
		e.metrics.totalLatency += time.Since(start)
		e.metrics.mu.Unlock()
	}()

	// Generate request ID for variable scoping
	requestID := uuid.New().String()
	defer e.variables.ClearRequest(requestID)

	// Get active rules for responses
	rules := e.GetActiveRules(DirectionResponse)

	// Apply each matching rule
	for _, rule := range rules {
		if e.matcher.MatchesScope(rule, resp.Request, true) {
			// Evaluate conditions
			if e.matcher.EvaluateConditions(rule, resp.Request, resp.StatusCode, resp.Header, nil, requestID) {
				ruleStart := time.Now()

				// Execute actions
				if err := e.executor.ExecuteResponseActions(rule, resp, requestID); err != nil {
					e.logger.Warn("failed to execute rule actions",
						"rule", rule.Name,
						"error", err,
					)
				} else {
					e.trackRuleExecution(rule.ID, time.Since(ruleStart))
				}
			}
		}
	}

	return resp, nil
}

// GetActiveRules returns all enabled rules for the given direction, sorted by priority.
func (e *Engine) GetActiveRules(direction Direction) []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var active []*Rule
	for _, rule := range e.rulesCache {
		if !rule.Enabled {
			continue
		}

		// Check if rule applies to this direction
		if rule.Scope.Direction == direction || rule.Scope.Direction == DirectionBoth {
			active = append(active, rule)
		}
	}

	// Sort by priority (higher first)
	sort.Slice(active, func(i, j int) bool {
		return active[i].Priority > active[j].Priority
	})

	return active
}

// trackRuleExecution tracks performance metrics for a rule.
func (e *Engine) trackRuleExecution(ruleID int, latency time.Duration) {
	e.metrics.mu.Lock()
	defer e.metrics.mu.Unlock()

	e.metrics.rulesApplied++
	e.metrics.ruleExecutions[ruleID]++
	e.metrics.ruleLatencies[ruleID] += latency

	// Calculate average latency
	avgLatency := e.metrics.ruleLatencies[ruleID] / time.Duration(e.metrics.ruleExecutions[ruleID])
	e.metrics.slowRules[ruleID] = avgLatency

	// Alert if rule is slow (>50ms)
	if avgLatency > 50*time.Millisecond {
		e.logger.Warn("slow rule detected",
			"rule_id", ruleID,
			"avg_latency", avgLatency,
			"executions", e.metrics.ruleExecutions[ruleID],
		)
	}
}

// GetMetrics returns current performance metrics.
func (e *Engine) GetMetrics() MetricsSnapshot {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()

	avgLatency := time.Duration(0)
	if e.metrics.totalRequests+e.metrics.totalResponses > 0 {
		avgLatency = e.metrics.totalLatency / time.Duration(e.metrics.totalRequests+e.metrics.totalResponses)
	}

	return MetricsSnapshot{
		TotalRequests:  e.metrics.totalRequests,
		TotalResponses: e.metrics.totalResponses,
		RulesApplied:   e.metrics.rulesApplied,
		AverageLatency: avgLatency,
		SlowRules:      copyMap(e.metrics.slowRules),
	}
}

// MetricsSnapshot represents a point-in-time snapshot of metrics.
type MetricsSnapshot struct {
	TotalRequests  int64
	TotalResponses int64
	RulesApplied   int64
	AverageLatency time.Duration
	SlowRules      map[int]time.Duration
}

func copyMap(m map[int]time.Duration) map[int]time.Duration {
	result := make(map[int]time.Duration, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// Rule Management Methods

// CreateRule creates a new rule.
func (e *Engine) CreateRule(ctx context.Context, rule *Rule) error {
	if err := rule.Validate(); err != nil {
		return err
	}

	rule.CreatedAt = time.Now()
	rule.ModifiedAt = time.Now()
	rule.Version = 1

	if err := e.storage.CreateRule(ctx, rule); err != nil {
		return err
	}

	return e.RefreshCache()
}

// UpdateRule updates an existing rule.
func (e *Engine) UpdateRule(ctx context.Context, rule *Rule) error {
	if err := rule.Validate(); err != nil {
		return err
	}

	rule.ModifiedAt = time.Now()
	rule.Version++

	if err := e.storage.UpdateRule(ctx, rule); err != nil {
		return err
	}

	return e.RefreshCache()
}

// DeleteRule deletes a rule by ID.
func (e *Engine) DeleteRule(ctx context.Context, id int) error {
	if err := e.storage.DeleteRule(ctx, id); err != nil {
		return err
	}

	return e.RefreshCache()
}

// GetRule retrieves a rule by ID.
func (e *Engine) GetRule(ctx context.Context, id int) (*Rule, error) {
	return e.storage.GetRule(ctx, id)
}

// ListRules returns all rules.
func (e *Engine) ListRules(ctx context.Context) ([]*Rule, error) {
	return e.storage.ListRules()
}

// EnableRule enables a rule.
func (e *Engine) EnableRule(ctx context.Context, id int) error {
	rule, err := e.storage.GetRule(ctx, id)
	if err != nil {
		return err
	}

	rule.Enabled = true
	if err := e.storage.UpdateRule(ctx, rule); err != nil {
		return err
	}

	return e.RefreshCache()
}

// DisableRule disables a rule.
func (e *Engine) DisableRule(ctx context.Context, id int) error {
	rule, err := e.storage.GetRule(ctx, id)
	if err != nil {
		return err
	}

	rule.Enabled = false
	if err := e.storage.UpdateRule(ctx, rule); err != nil {
		return err
	}

	return e.RefreshCache()
}

// ImportRules imports rules from JSON.
func (e *Engine) ImportRules(ctx context.Context, rules []*Rule) error {
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("invalid rule %s: %w", rule.Name, err)
		}

		rule.CreatedAt = time.Now()
		rule.ModifiedAt = time.Now()
		if rule.Version == 0 {
			rule.Version = 1
		}

		if err := e.storage.CreateRule(ctx, rule); err != nil {
			return err
		}
	}

	return e.RefreshCache()
}

// ExportRules exports all rules to JSON format.
func (e *Engine) ExportRules(ctx context.Context) ([]*Rule, error) {
	return e.storage.ListRules()
}

// GetStorage returns the storage instance (for API access).
func (e *Engine) GetStorage() *Storage {
	return e.storage
}
