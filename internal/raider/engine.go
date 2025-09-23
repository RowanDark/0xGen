package raider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultConcurrency  = 1
	defaultCaptureBytes = 512
	defaultBackoff      = time.Second
)

// Engine executes a fuzzing run against the supplied request template.
type Engine struct {
	template    *Template
	payloads    []string
	client      *http.Client
	concurrency int
	rate        float64
	capture     int
}

// EngineOption configures the fuzzer execution behaviour.
type EngineOption func(*Engine)

// WithConcurrency overrides the worker pool size.
func WithConcurrency(n int) EngineOption {
	return func(e *Engine) {
		if n > 0 {
			e.concurrency = n
		}
	}
}

// WithRateLimit specifies the per-host request rate in requests per second.
func WithRateLimit(limit float64) EngineOption {
	return func(e *Engine) {
		if limit > 0 {
			e.rate = limit
		}
	}
}

// WithHTTPClient allows injecting a custom HTTP client.
func WithHTTPClient(client *http.Client) EngineOption {
	return func(e *Engine) {
		if client != nil {
			e.client = client
		}
	}
}

// WithCaptureLimit sets how many bytes of request/response bodies are
// preserved in the output metadata.
func WithCaptureLimit(limit int) EngineOption {
	return func(e *Engine) {
		if limit > 0 {
			e.capture = limit
		}
	}
}

// NewEngine constructs a new Engine for the provided template and payloads.
func NewEngine(tpl *Template, payloads []string, opts ...EngineOption) *Engine {
	e := &Engine{template: tpl, payloads: append([]string(nil), payloads...), concurrency: defaultConcurrency, capture: defaultCaptureBytes}
	e.client = &http.Client{Timeout: 30 * time.Second}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

type job struct {
	position Position
	payload  string
}

type hostState struct {
	mu      sync.Mutex
	rate    float64
	next    time.Time
	backoff time.Time
}

func (s *hostState) wait(ctx context.Context) error {
	s.mu.Lock()
	now := time.Now()
	waitUntil := now
	var interval time.Duration
	if s.rate > 0 {
		interval = time.Duration(float64(time.Second) / s.rate)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		if now.Before(s.next) {
			waitUntil = s.next
		}
		if waitUntil.Before(now) {
			waitUntil = now
		}
		s.next = waitUntil.Add(interval)
	}
	if s.backoff.After(waitUntil) {
		waitUntil = s.backoff
		if interval > 0 {
			s.next = waitUntil.Add(interval)
		}
	}
	s.mu.Unlock()

	sleep := time.Until(waitUntil)
	if sleep <= 0 {
		return nil
	}

	timer := time.NewTimer(sleep)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	return nil
}

func (s *hostState) backoffFor(d time.Duration) {
	if d <= 0 {
		d = defaultBackoff
	}
	s.mu.Lock()
	until := time.Now().Add(d)
	if until.After(s.backoff) {
		s.backoff = until
	}
	s.mu.Unlock()
}

// Result captures the outcome for a single request/response pair.
type Result struct {
	Position Position        `json:"position"`
	Payload  string          `json:"payload"`
	Request  MessageSnapshot `json:"request"`
	Response MessageSnapshot `json:"response"`
	Status   string          `json:"status"`
	Duration int64           `json:"duration_ms"`
	Error    string          `json:"error,omitempty"`
	Time     time.Time       `json:"time"`
}

// MessageSnapshot stores the truncated details for a HTTP message.
type MessageSnapshot struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// Run executes the fuzzing workflow. For each request result the callback is
// invoked. Returning an error from the callback aborts the run.
func (e *Engine) Run(ctx context.Context, cb func(Result) error) error {
	if e.template == nil {
		return errors.New("template is required")
	}
	if len(e.payloads) == 0 {
		return errors.New("at least one payload is required")
	}

	positions := e.template.Positions()
	if len(positions) == 0 {
		return errors.New("no insertion points found in template")
	}

	jobs := make(chan job)
	var wg sync.WaitGroup
	hostStates := sync.Map{}

	workers := e.concurrency
	if workers < 1 {
		workers = defaultConcurrency
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := range jobs {
				res := e.execute(ctx, &hostStates, j)
				if cb != nil {
					if err := cb(res); err != nil {
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, pos := range positions {
			for _, payload := range e.payloads {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{position: pos, payload: payload}:
				}
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		<-done
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (e *Engine) execute(ctx context.Context, states *sync.Map, j job) Result {
	rendered := e.template.RenderWith(j.position.Index, j.payload)
	req, body, err := buildRequest(ctx, rendered)
	if err != nil {
		return Result{Position: j.position, Payload: j.payload, Error: err.Error(), Time: time.Now().UTC()}
	}

	host := requestHost(req)
	state := getHostState(states, host, e.rate)
	if err := state.wait(ctx); err != nil {
		return Result{Position: j.position, Payload: j.payload, Error: err.Error(), Time: time.Now().UTC()}
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	duration := time.Since(start)

	result := Result{
		Position: j.position,
		Payload:  j.payload,
		Duration: duration.Milliseconds(),
		Time:     time.Now().UTC(),
		Request:  snapshotRequest(req, body, e.capture),
	}

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, int64(e.capture)))
	result.Response = snapshotResponse(resp, string(responseBody), e.capture)
	result.Status = resp.Status

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		backoff := parseRetryAfter(resp.Header.Get("Retry-After"))
		state.backoffFor(backoff)
	}

	return result
}

func buildRequest(ctx context.Context, raw string) (*http.Request, []byte, error) {
	reader := bufio.NewReader(strings.NewReader(raw))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("parse request: %w", err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read request body: %w", err)
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	req.ContentLength = int64(len(body))

	if req.URL.Scheme == "" {
		if strings.HasPrefix(req.RequestURI, "http://") || strings.HasPrefix(req.RequestURI, "https://") {
			parsed, err := url.Parse(req.RequestURI)
			if err != nil {
				return nil, nil, fmt.Errorf("parse request url: %w", err)
			}
			req.URL = parsed
		} else {
			host := req.Host
			if host == "" {
				host = req.Header.Get("Host")
			}
			if host == "" {
				return nil, nil, errors.New("request missing host header")
			}
			req.URL = &url.URL{Scheme: "http", Host: host, Path: req.RequestURI}
		}
	}

	if req.Host == "" {
		req.Host = req.URL.Host
	}

	req.RequestURI = ""
	return req.WithContext(ctx), body, nil
}

func getHostState(states *sync.Map, host string, rate float64) *hostState {
	if host == "" {
		host = "default"
	}
	actual, _ := states.LoadOrStore(host, &hostState{rate: rate})
	state := actual.(*hostState)
	if rate > 0 {
		state.mu.Lock()
		state.rate = rate
		state.mu.Unlock()
	}
	return state
}

func requestHost(req *http.Request) string {
	if req == nil {
		return ""
	}
	if req.URL != nil && req.URL.Host != "" {
		return req.URL.Host
	}
	return req.Host
}

func snapshotRequest(req *http.Request, body []byte, limit int) MessageSnapshot {
	snap := MessageSnapshot{}
	if req == nil {
		return snap
	}
	snap.Method = req.Method
	if req.URL != nil {
		snap.URL = req.URL.String()
	}
	snap.Headers = flattenHeaders(req.Header)
	if len(body) > 0 {
		snap.Body = truncate(string(body), limit)
	}
	return snap
}

func snapshotResponse(resp *http.Response, body string, limit int) MessageSnapshot {
	snap := MessageSnapshot{Headers: flattenHeaders(resp.Header)}
	if resp.Request != nil {
		snap.Method = resp.Request.Method
		if resp.Request.URL != nil {
			snap.URL = resp.Request.URL.String()
		}
	}
	snap.Body = truncate(body, limit)
	return snap
}

func flattenHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, "; ")
	}
	return out
}

func truncate(body string, limit int) string {
	if limit <= 0 || len(body) <= limit {
		return body
	}
	if limit < 3 {
		return body[:limit]
	}
	return body[:limit-3] + "..."
}

func parseRetryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return defaultBackoff
	}
	if secs, err := strconv.Atoi(header); err == nil {
		if secs <= 0 {
			return defaultBackoff
		}
		return time.Duration(secs) * time.Second
	}
	if ts, err := http.ParseTime(header); err == nil {
		now := time.Now()
		if ts.After(now) {
			return ts.Sub(now)
		}
	}
	return defaultBackoff
}

// EncodeResult writes the result as a JSONL line to the provided writer.
func EncodeResult(w io.Writer, res Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(res)
}
