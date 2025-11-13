package blitz

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Engine is the main fuzzing engine that coordinates all components.
type Engine struct {
	config     *EngineConfig
	analyzer   *Analyzer
	strategy   AttackStrategy
	classifier *AIClassifier
	correlator *FindingsCorrelator
}

// NewEngine creates a new Blitz fuzzing engine.
func NewEngine(config *EngineConfig) (*Engine, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if config.Request == nil {
		return nil, fmt.Errorf("request template is required")
	}

	if len(config.Generators) == 0 {
		return nil, fmt.Errorf("at least one payload generator is required")
	}

	if config.Client == nil {
		config.Client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	if config.Concurrency <= 0 {
		config.Concurrency = 1
	}

	if config.CaptureLimit <= 0 {
		config.CaptureLimit = 512
	}

	strategy, err := GetStrategy(config.AttackType)
	if err != nil {
		return nil, fmt.Errorf("get strategy: %w", err)
	}

	analyzer := NewAnalyzer(config.Analyzer)

	engine := &Engine{
		config:   config,
		analyzer: analyzer,
		strategy: strategy,
	}

	// Initialize AI components if enabled
	if config.EnableAIClassification {
		engine.classifier = NewAIClassifier()
	}

	if config.EnableFindingsCorrelation {
		sessionID := fmt.Sprintf("blitz_%d", time.Now().Unix())
		if config.Storage != nil {
			if sqlStorage, ok := config.Storage.(*SQLiteStorage); ok {
				sessionID = sqlStorage.GetSessionID()
			}
		}
		engine.correlator = NewFindingsCorrelator(sessionID)
	}

	return engine, nil
}

// Run executes the fuzzing campaign with the configured parameters.
func (e *Engine) Run(ctx context.Context, callback func(*FuzzResult) error) error {
	// Generate all payloads from generators
	payloadSets, err := e.generatePayloadSets()
	if err != nil {
		return fmt.Errorf("generate payloads: %w", err)
	}

	// Generate jobs based on attack type
	jobs, err := e.strategy.GenerateJobs(e.config.Request.Positions, payloadSets)
	if err != nil {
		return fmt.Errorf("generate jobs: %w", err)
	}

	if len(jobs) == 0 {
		return fmt.Errorf("no jobs generated")
	}

	// Execute jobs with worker pool
	return e.executeJobs(ctx, jobs, callback)
}

// generatePayloadSets generates payloads from all configured generators.
func (e *Engine) generatePayloadSets() ([][]string, error) {
	var payloadSets [][]string

	for _, gen := range e.config.Generators {
		payloads, err := gen.Generate()
		if err != nil {
			return nil, fmt.Errorf("generator %s: %w", gen.Name(), err)
		}
		payloadSets = append(payloadSets, payloads)
	}

	return payloadSets, nil
}

// executeJobs runs all fuzzing jobs with the configured concurrency.
func (e *Engine) executeJobs(ctx context.Context, jobs []AttackJob, callback func(*FuzzResult) error) error {
	jobChan := make(chan AttackJob, e.config.Concurrency*2)
	resultChan := make(chan *FuzzResult, e.config.Concurrency*2)

	var wg sync.WaitGroup
	errChan := make(chan error, 1)

	// Rate limiter (if configured)
	var rateLimiter <-chan time.Time
	if e.config.RateLimit > 0 {
		interval := time.Duration(float64(time.Second) / e.config.RateLimit)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	// Start workers
	for i := 0; i < e.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Rate limiting
				if rateLimiter != nil {
					select {
					case <-rateLimiter:
					case <-ctx.Done():
						return
					}
				}

				result := e.executeJob(ctx, job)
				select {
				case resultChan <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Result handler
	go func() {
		for result := range resultChan {
			// Analyze response
			e.analyzer.Analyze(result)

			// AI Classification
			if e.classifier != nil && result.Anomaly != nil && result.Anomaly.IsInteresting {
				classifications := e.classifier.ClassifyWithContext(result, result.Payload)

				// Store classifications in metadata (if storage exists)
				if len(classifications) > 0 && e.config.Storage != nil {
					// Note: Classifications are processed by correlator for findings
					_ = classifications // Used by correlator below
				}
			}

			// Store if configured
			if e.config.Storage != nil {
				if err := e.config.Storage.Store(result); err != nil {
					select {
					case errChan <- fmt.Errorf("store result: %w", err):
					default:
					}
					return
				}
			}

			// Findings Correlation
			if e.correlator != nil && result.Anomaly != nil && result.Anomaly.IsInteresting {
				resultFindings := e.correlator.CorrelateResult(result)

				// Emit findings via callback
				if e.config.FindingsCallback != nil {
					for _, finding := range resultFindings {
						if err := e.config.FindingsCallback(finding); err != nil {
							select {
							case errChan <- fmt.Errorf("findings callback: %w", err):
							default:
							}
							return
						}
					}
				}
			}

			// Callback
			if callback != nil {
				if err := callback(result); err != nil {
					select {
					case errChan <- err:
					default:
					}
					return
				}
			}
		}
	}()

	// Feed jobs
	go func() {
		defer close(jobChan)
		for _, job := range jobs {
			select {
			case jobChan <- job:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for workers to finish
	wg.Wait()
	close(resultChan)

	// Check for errors
	select {
	case err := <-errChan:
		return err
	default:
	}

	return ctx.Err()
}

// executeJob performs a single fuzzing request with retry logic.
func (e *Engine) executeJob(ctx context.Context, job AttackJob) *FuzzResult {
	var lastErr error

	maxRetries := e.config.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		result := e.executeRequest(ctx, job)

		// If successful or non-retryable error, return
		if result.Error == "" || !isRetryableError(result.Error) {
			return result
		}

		lastErr = errors.New(result.Error)

		// Exponential backoff
		if attempt < maxRetries {
			backoff := time.Duration(attempt+1) * 500 * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return result
			}
		}
	}

	// Final result with retry exhausted
	result := &FuzzResult{
		RequestID:    generateRequestID(job),
		Position:     job.PrimaryPos,
		PositionName: e.getPositionName(job.PrimaryPos),
		Payload:      job.PrimaryValue,
		PayloadSet:   job.PayloadMap,
		Error:        fmt.Sprintf("max retries exceeded: %v", lastErr),
		Timestamp:    time.Now().UTC(),
	}

	return result
}

// executeRequest performs a single HTTP request.
func (e *Engine) executeRequest(ctx context.Context, job AttackJob) *FuzzResult {
	// Render request with payloads
	renderedReq := e.config.Request.Render(job.PayloadMap)

	// Build HTTP request
	req, bodyBytes, err := buildHTTPRequest(ctx, renderedReq)
	if err != nil {
		return &FuzzResult{
			RequestID:    generateRequestID(job),
			Position:     job.PrimaryPos,
			PositionName: e.getPositionName(job.PrimaryPos),
			Payload:      job.PrimaryValue,
			PayloadSet:   job.PayloadMap,
			Error:        fmt.Sprintf("build request: %v", err),
			Timestamp:    time.Now().UTC(),
		}
	}

	// Execute request
	start := time.Now()
	resp, err := e.config.Client.Do(req)
	duration := time.Since(start)

	result := &FuzzResult{
		RequestID:    generateRequestID(job),
		Position:     job.PrimaryPos,
		PositionName: e.getPositionName(job.PrimaryPos),
		Payload:      job.PrimaryValue,
		PayloadSet:   job.PayloadMap,
		Duration:     duration.Milliseconds(),
		Timestamp:    time.Now().UTC(),
		Request:      CaptureRequest(req, bodyBytes, e.config.CaptureLimit),
	}

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	// Read response body
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, int64(e.config.CaptureLimit*2)))

	result.StatusCode = resp.StatusCode
	result.ContentLen = int64(len(respBody))
	result.Response = CaptureResponse(resp, string(respBody), e.config.CaptureLimit)

	return result
}

// getPositionName returns the name of a position by index.
func (e *Engine) getPositionName(index int) string {
	for _, pos := range e.config.Request.Positions {
		if pos.Index == index {
			return pos.Name
		}
	}
	return fmt.Sprintf("position_%d", index)
}

// buildHTTPRequest parses a raw HTTP request string into an http.Request.
func buildHTTPRequest(ctx context.Context, raw string) (*http.Request, []byte, error) {
	reader := bufio.NewReader(strings.NewReader(raw))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("parse request: %w", err)
	}

	// Read body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read body: %w", err)
	}
	req.Body.Close()

	// Restore body
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	req.ContentLength = int64(len(body))

	// Build URL if not absolute
	if req.URL.Scheme == "" {
		if strings.HasPrefix(req.RequestURI, "http://") || strings.HasPrefix(req.RequestURI, "https://") {
			parsed, err := url.Parse(req.RequestURI)
			if err != nil {
				return nil, nil, fmt.Errorf("parse URL: %w", err)
			}
			req.URL = parsed
		} else {
			host := req.Host
			if host == "" {
				host = req.Header.Get("Host")
			}
			if host == "" {
				return nil, nil, errors.New("request missing host")
			}
			req.URL = &url.URL{
				Scheme: "https",
				Host:   host,
				Path:   req.RequestURI,
			}
		}
	}

	if req.Host == "" {
		req.Host = req.URL.Host
	}

	req.RequestURI = ""
	return req.WithContext(ctx), body, nil
}

// generateRequestID creates a unique identifier for a fuzzing request.
func generateRequestID(job AttackJob) string {
	hash := md5.New()
	for idx, payload := range job.PayloadMap {
		fmt.Fprintf(hash, "%d:%s;", idx, payload)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))[:12]
}

// isRetryableError determines if an error should trigger a retry.
func isRetryableError(errStr string) bool {
	retryable := []string{
		"timeout",
		"connection reset",
		"connection refused",
		"EOF",
		"temporary failure",
	}

	errLower := strings.ToLower(errStr)
	for _, pattern := range retryable {
		if strings.Contains(errLower, pattern) {
			return true
		}
	}

	return false
}

// GetAnalyzer returns the engine's analyzer for inspection.
func (e *Engine) GetAnalyzer() *Analyzer {
	return e.analyzer
}
