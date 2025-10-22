package hotreload

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/0xgen/internal/bus"
	"github.com/RowanDark/0xgen/internal/logging"
	"github.com/RowanDark/0xgen/internal/plugins"
	"github.com/RowanDark/0xgen/internal/plugins/integrity"
)

const defaultPollInterval = time.Second

// Reloader watches the plugin directory for new or updated manifests and reloads
// plugins without requiring a 0xgend restart.
type Reloader struct {
	dir           string
	repoRoot      string
	allowlistPath string
	pollInterval  time.Duration
	audit         *logging.AuditLogger
	bus           interface {
		DisconnectPlugin(pluginName, reason string) int
	}

	mu      sync.RWMutex
	plugins map[string]PluginState
}

// PluginState captures the currently active plugin snapshot tracked by the
// reloader.
type PluginState struct {
	Name         string
	Version      string
	ManifestPath string
	ArtifactPath string
	ArtifactHash string
	LoadedAt     time.Time
}

// Option configures the reloader.
type Option func(*Reloader)

// WithPollInterval overrides the default polling cadence.
func WithPollInterval(interval time.Duration) Option {
	return func(r *Reloader) {
		if interval > 0 {
			r.pollInterval = interval
		}
	}
}

// WithAuditLogger sets the audit logger used when emitting plugin lifecycle
// events.
func WithAuditLogger(logger *logging.AuditLogger) Option {
	return func(r *Reloader) {
		if logger != nil {
			r.audit = logger
		}
	}
}

// New constructs a hot reloader for the provided plugin directory. The
// allowlistPath may be empty when allowlist enforcement is not required.
func New(pluginDir, repoRoot, allowlistPath string, busServer *bus.Server, opts ...Option) (*Reloader, error) {
	if strings.TrimSpace(pluginDir) == "" {
		return nil, errors.New("plugin directory is required")
	}
	absDir, err := filepath.Abs(pluginDir)
	if err != nil {
		return nil, fmt.Errorf("resolve plugin directory: %w", err)
	}
	info, err := os.Stat(absDir)
	if err != nil {
		return nil, fmt.Errorf("stat plugin directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("plugin directory %s is not a directory", absDir)
	}

	absAllowlist := strings.TrimSpace(allowlistPath)
	if absAllowlist != "" {
		absAllowlist, err = filepath.Abs(absAllowlist)
		if err != nil {
			return nil, fmt.Errorf("resolve allowlist path: %w", err)
		}
	}
	if strings.TrimSpace(repoRoot) != "" {
		repoRoot, err = filepath.Abs(repoRoot)
		if err != nil {
			return nil, fmt.Errorf("resolve repository root: %w", err)
		}
	}

	r := &Reloader{
		dir:           absDir,
		repoRoot:      repoRoot,
		allowlistPath: absAllowlist,
		pollInterval:  defaultPollInterval,
		audit:         logging.MustNewAuditLogger("plugin_manager"),
		bus:           busServer,
		plugins:       make(map[string]PluginState),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// Start begins monitoring the plugin directory until the context is cancelled.
func (r *Reloader) Start(ctx context.Context) {
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	r.scan()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.scan()
		}
	}
}

// Plugins returns a copy of the known plugin state. It is intended for testing
// and introspection.
func (r *Reloader) Plugins() map[string]PluginState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snapshot := make(map[string]PluginState, len(r.plugins))
	for k, v := range r.plugins {
		snapshot[k] = v
	}
	return snapshot
}

func (r *Reloader) scan() {
	manifests, err := r.discoverManifests()
	if err != nil {
		r.emit(logging.AuditEvent{
			EventType: logging.EventPluginDisconnect,
			Decision:  logging.DecisionDeny,
			Reason:    err.Error(),
			Metadata: map[string]any{
				"phase": "discover",
			},
		})
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Handle removals.
	for name, state := range r.plugins {
		_, ok := manifests[name]
		if ok {
			continue
		}
		if _, err := os.Stat(state.ManifestPath); err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
				delete(r.plugins, name)
				r.emit(logging.AuditEvent{
					EventType: logging.EventPluginDisconnect,
					Decision:  logging.DecisionInfo,
					PluginID:  name,
					Reason:    "plugin removed from filesystem",
					Metadata: map[string]any{
						"manifest": state.ManifestPath,
					},
				})
				if r.bus != nil {
					r.bus.DisconnectPlugin(name, "plugin removed")
				}
			}
		}
	}

	// Handle additions and updates.
	for name, manifest := range manifests {
		current, ok := r.plugins[name]
		if ok && current.ArtifactHash == manifest.ArtifactHash {
			continue
		}

		if ok && r.bus != nil {
			r.bus.DisconnectPlugin(name, "plugin hot reload")
		}

		r.plugins[name] = manifest
		metadata := map[string]any{
			"version":       manifest.Version,
			"manifest_path": manifest.ManifestPath,
			"artifact_path": manifest.ArtifactPath,
		}
		if ok {
			metadata["previous_hash"] = current.ArtifactHash
			metadata["previous_version"] = current.Version
		}
		r.emit(logging.AuditEvent{
			EventType: logging.EventPluginLoad,
			Decision:  logging.DecisionAllow,
			PluginID:  name,
			Metadata:  metadata,
		})
	}
}

func (r *Reloader) discoverManifests() (map[string]PluginState, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, fmt.Errorf("read plugin directory: %w", err)
	}

	allowlist, err := r.loadAllowlist()
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	manifests := make(map[string]PluginState)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(r.dir, entry.Name(), "manifest.json")
		manifest, err := plugins.LoadManifest(manifestPath)
		if err != nil {
			r.emit(logging.AuditEvent{
				EventType: logging.EventPluginDisconnect,
				Decision:  logging.DecisionDeny,
				Reason:    fmt.Sprintf("load manifest: %v", err),
				Metadata: map[string]any{
					"manifest_path": manifestPath,
				},
			})
			continue
		}

		artifactPath := manifest.Artifact
		if !filepath.IsAbs(artifactPath) {
			artifactPath = filepath.Join(filepath.Dir(manifestPath), artifactPath)
		}
		artifactPath = filepath.Clean(artifactPath)

		if allowlist != nil {
			if err := allowlist.Verify(artifactPath); err != nil {
				r.emit(logging.AuditEvent{
					EventType: logging.EventPluginDisconnect,
					Decision:  logging.DecisionDeny,
					PluginID:  manifest.Name,
					Reason:    fmt.Sprintf("allowlist validation failed: %v", err),
					Metadata: map[string]any{
						"artifact_path": artifactPath,
					},
				})
				continue
			}
		}
		if err := integrity.VerifySignature(artifactPath, filepath.Dir(manifestPath), r.repoRoot, manifest.Signature); err != nil {
			r.emit(logging.AuditEvent{
				EventType: logging.EventPluginDisconnect,
				Decision:  logging.DecisionDeny,
				PluginID:  manifest.Name,
				Reason:    fmt.Sprintf("signature verification failed: %v", err),
				Metadata: map[string]any{
					"artifact_path": artifactPath,
				},
			})
			continue
		}

		hash, err := integrity.HashFile(artifactPath)
		if err != nil {
			r.emit(logging.AuditEvent{
				EventType: logging.EventPluginDisconnect,
				Decision:  logging.DecisionDeny,
				PluginID:  manifest.Name,
				Reason:    fmt.Sprintf("hash artifact: %v", err),
				Metadata: map[string]any{
					"artifact_path": artifactPath,
				},
			})
			continue
		}

		manifests[manifest.Name] = PluginState{
			Name:         manifest.Name,
			Version:      manifest.Version,
			ManifestPath: manifestPath,
			ArtifactPath: artifactPath,
			ArtifactHash: hash,
			LoadedAt:     time.Now().UTC(),
		}
	}
	return manifests, nil
}

func (r *Reloader) loadAllowlist() (*integrity.Allowlist, error) {
	if strings.TrimSpace(r.allowlistPath) == "" {
		return nil, nil
	}
	allowlist, err := integrity.LoadAllowlist(r.allowlistPath)
	if err != nil {
		r.emit(logging.AuditEvent{
			EventType: logging.EventPluginDisconnect,
			Decision:  logging.DecisionDeny,
			Reason:    fmt.Sprintf("load allowlist: %v", err),
			Metadata: map[string]any{
				"allowlist_path": r.allowlistPath,
			},
		})
		return nil, err
	}
	return allowlist, nil
}

func (r *Reloader) emit(event logging.AuditEvent) {
	if r.audit == nil {
		return
	}
	if err := r.audit.Emit(event); err != nil {
		fmt.Fprintf(os.Stderr, "plugin manager audit log error: %v\n", err)
	}
}
