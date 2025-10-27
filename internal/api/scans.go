package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/logging"
	"github.com/RowanDark/0xgen/internal/plugins/launcher"
	"github.com/RowanDark/0xgen/internal/plugins/local"
	"github.com/RowanDark/0xgen/internal/reporter"
)

const (
	scanStatusQueued    = "queued"
	scanStatusRunning   = "running"
	scanStatusSucceeded = "succeeded"
	scanStatusFailed    = "failed"
)

// ManagerConfig configures scan execution.
type ManagerConfig struct {
	PluginsDir     string
	AllowlistPath  string
	RepoRoot       string
	ServerAddr     string
	AuthToken      string
	SigningKeyPath string
	ScanTimeout    time.Duration
}

// Manager orchestrates plugin executions and captures findings for API responses.
type Manager struct {
	cfg      ManagerConfig
	findings *findings.Bus
	logger   *logging.AuditLogger

	mu    sync.RWMutex
	scans map[string]*Scan

	queue   chan *Scan
	startWG sync.WaitGroup
}

// Scan describes the lifecycle of a single plugin invocation.
type Scan struct {
	ID          string             `json:"id"`
	Plugin      string             `json:"plugin"`
	Status      string             `json:"status"`
	CreatedAt   time.Time          `json:"created_at"`
	StartedAt   *time.Time         `json:"started_at,omitempty"`
	CompletedAt *time.Time         `json:"completed_at,omitempty"`
	Error       string             `json:"error,omitempty"`
	Logs        string             `json:"logs,omitempty"`
	Findings    []findings.Finding `json:"findings,omitempty"`
	Signature   string             `json:"signature,omitempty"`
	Digest      string             `json:"digest,omitempty"`
}

// ScanResult bundles the signed results returned by the API.
type ScanResult struct {
	ScanID      string             `json:"scan_id"`
	Plugin      string             `json:"plugin"`
	GeneratedAt time.Time          `json:"generated_at"`
	Findings    []findings.Finding `json:"findings"`
}

// NewManager constructs a scan manager.
func NewManager(cfg ManagerConfig, bus *findings.Bus, logger *logging.AuditLogger) *Manager {
	return &Manager{
		cfg:      cfg,
		findings: bus,
		logger:   logger,
		scans:    make(map[string]*Scan),
		queue:    make(chan *Scan, 4),
	}
}

// Start launches the background worker that processes queued scans.
func (m *Manager) Start(ctx context.Context) {
	m.startWG.Add(1)
	go func() {
		defer m.startWG.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case scan := <-m.queue:
				if scan == nil {
					return
				}
				m.runScan(ctx, scan)
			}
		}
	}()
}

// Stop waits for the background worker to exit.
func (m *Manager) Stop() {
	close(m.queue)
	m.startWG.Wait()
}

// Enqueue registers a new scan request for the provided plugin.
func (m *Manager) Enqueue(plugin string) (*Scan, error) {
	plugin = strings.TrimSpace(plugin)
	if plugin == "" {
		return nil, errors.New("plugin is required")
	}
	if m.findings == nil {
		return nil, errors.New("findings bus not configured")
	}

	scan := &Scan{
		ID:        uuid.NewString(),
		Plugin:    plugin,
		Status:    scanStatusQueued,
		CreatedAt: time.Now().UTC(),
	}

	m.mu.Lock()
	m.scans[scan.ID] = scan
	m.mu.Unlock()

	select {
	case m.queue <- scan:
	default:
		// If the queue is full, block to preserve ordering.
		m.queue <- scan
	}
	return copyScan(scan), nil
}

// Get returns a copy of the scan metadata for the provided identifier.
func (m *Manager) Get(id string) (*Scan, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	scan, ok := m.scans[id]
	if !ok {
		return nil, false
	}
	return copyScan(scan), true
}

// Result returns the signed results for the completed scan.
func (m *Manager) Result(id string) (*ScanResult, string, string, error) {
	m.mu.RLock()
	scan, ok := m.scans[id]
	m.mu.RUnlock()
	if !ok {
		return nil, "", "", errors.New("scan not found")
	}
	if scan.Status != scanStatusSucceeded {
		return nil, "", "", fmt.Errorf("scan %s is not complete", id)
	}
	generated := time.Now().UTC()
	if scan.CompletedAt != nil {
		generated = scan.CompletedAt.UTC()
	}
	result := &ScanResult{
		ScanID:      scan.ID,
		Plugin:      scan.Plugin,
		GeneratedAt: generated,
		Findings:    cloneFindings(scan.Findings),
	}
	return result, scan.Signature, scan.Digest, nil
}

func (m *Manager) runScan(ctx context.Context, scan *Scan) {
	start := time.Now().UTC()
	m.updateStatus(scan.ID, func(s *Scan) {
		s.Status = scanStatusRunning
		s.StartedAt = &start
	})

	var logs bytes.Buffer
	subCtx, subCancel := context.WithCancel(ctx)
	findingsCh := m.findings.Subscribe(subCtx)
	collected := make([]findings.Finding, 0, 16)
	var collectMu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range findingsCh {
			if !strings.HasPrefix(f.Plugin, scan.Plugin) && f.Plugin != scan.Plugin {
				continue
			}
			collectMu.Lock()
			collected = append(collected, f)
			collectMu.Unlock()
		}
	}()

	timeout := m.cfg.ScanTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	if cancel != nil {
		defer cancel()
	}

	manifestPath, err := m.resolveManifest(scan.Plugin)
	if err != nil {
		subCancel()
		<-done
		m.fail(scan.ID, fmt.Errorf("resolve manifest: %w", err), logs.String())
		return
	}

	cfg := launcher.Config{
		ManifestPath:  manifestPath,
		AllowlistPath: m.cfg.AllowlistPath,
		RepoRoot:      m.cfg.RepoRoot,
		ServerAddr:    m.cfg.ServerAddr,
		AuthToken:     m.cfg.AuthToken,
		Duration:      timeout,
		Stdout:        &logs,
		Stderr:        &logs,
	}

	result, runErr := launcher.Run(runCtx, cfg)
	subCancel()
	<-done

	collectMu.Lock()
	findingsCopy := cloneFindings(collected)
	collectMu.Unlock()

	if runErr != nil {
		if errors.Is(runErr, context.DeadlineExceeded) {
			runErr = fmt.Errorf("scan timed out after %s", timeout)
		}
		m.fail(scan.ID, runErr, logs.String())
		return
	}

	completed := time.Now().UTC()
	digest, signature, err := signFindings(scan.ID, findingsCopy, m.cfg.SigningKeyPath, result.Manifest.Name, completed)
	if err != nil {
		m.fail(scan.ID, fmt.Errorf("sign results: %w", err), logs.String())
		return
	}

	m.updateStatus(scan.ID, func(s *Scan) {
		s.Status = scanStatusSucceeded
		s.CompletedAt = &completed
		s.Findings = findingsCopy
		s.Signature = signature
		s.Digest = digest
		s.Logs = logs.String()
	})
}

func (m *Manager) fail(id string, err error, logs string) {
	completed := time.Now().UTC()
	m.updateStatus(id, func(s *Scan) {
		s.Status = scanStatusFailed
		s.CompletedAt = &completed
		s.Error = err.Error()
		s.Logs = logs
	})
}

func (m *Manager) updateStatus(id string, mutate func(*Scan)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	scan, ok := m.scans[id]
	if !ok {
		return
	}
	mutate(scan)
}

func (m *Manager) resolveManifest(plugin string) (string, error) {
	if strings.TrimSpace(m.cfg.PluginsDir) == "" {
		return "", errors.New("plugins directory not configured")
	}
	plugins, err := local.Discover(m.cfg.PluginsDir)
	if err != nil {
		return "", fmt.Errorf("discover plugins: %w", err)
	}
	for _, p := range plugins {
		if strings.EqualFold(p.Name, plugin) {
			return p.ManifestPath, nil
		}
	}
	return "", fmt.Errorf("plugin %s not found", plugin)
}

func cloneFindings(src []findings.Finding) []findings.Finding {
	if len(src) == 0 {
		return nil
	}
	out := make([]findings.Finding, len(src))
	copy(out, src)
	for i := range out {
		if len(src[i].Metadata) > 0 {
			meta := make(map[string]string, len(src[i].Metadata))
			for k, v := range src[i].Metadata {
				meta[k] = v
			}
			out[i].Metadata = meta
		}
	}
	return out
}

func copyScan(scan *Scan) *Scan {
	if scan == nil {
		return nil
	}
	clone := *scan
	clone.Findings = cloneFindings(scan.Findings)
	if scan.StartedAt != nil {
		started := *scan.StartedAt
		clone.StartedAt = &started
	}
	if scan.CompletedAt != nil {
		completed := *scan.CompletedAt
		clone.CompletedAt = &completed
	}
	return &clone
}

func signFindings(scanID string, findings []findings.Finding, signingKeyPath, plugin string, generated time.Time) (digest string, signature string, err error) {
	if signingKeyPath == "" {
		return "", "", errors.New("signing key path not configured")
	}
	payload := ScanResult{
		ScanID:      scanID,
		Plugin:      plugin,
		GeneratedAt: generated,
		Findings:    cloneFindings(findings),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("encode results: %w", err)
	}
	digest = reporter.ComputeBundleDigest(data)

	tmpFile, err := os.CreateTemp("", "0xgen-scan-*.json")
	if err != nil {
		return "", "", fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()
	if _, err := io.Copy(tmpFile, bytes.NewReader(data)); err != nil {
		tmpFile.Close()
		return "", "", fmt.Errorf("write temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", "", fmt.Errorf("close temp file: %w", err)
	}

	sigPath, err := reporter.SignArtifact(tmpFile.Name(), signingKeyPath)
	if err != nil {
		return "", "", err
	}
	defer func() {
		_ = os.Remove(sigPath)
	}()
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return "", "", fmt.Errorf("read signature: %w", err)
	}
	signature = strings.TrimSpace(string(sigData))
	return digest, signature, nil
}

// ListPlugins returns the currently installed plugins.
func (m *Manager) ListPlugins() ([]local.Plugin, error) {
	if strings.TrimSpace(m.cfg.PluginsDir) == "" {
		return nil, errors.New("plugins directory not configured")
	}
	return local.Discover(m.cfg.PluginsDir)
}
