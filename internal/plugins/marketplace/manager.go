package marketplace

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"

	"github.com/RowanDark/0xgen/internal/logging"
	"github.com/RowanDark/0xgen/internal/plugins"
	"github.com/RowanDark/0xgen/internal/plugins/integrity"
	"github.com/RowanDark/0xgen/internal/plugins/local"
	"github.com/RowanDark/0xgen/internal/registry"
)

const defaultSchemaVersion = "2025-02"

// Manager coordinates plugin marketplace operations.
type Manager struct {
	pluginsDir string
	allowlist  string
	registry   string
	client     *http.Client
	logger     *logging.AuditLogger
	mu         sync.Mutex
}

// Option configures the manager instance.
type Option func(*Manager)

// WithHTTPClient overrides the HTTP client used for downloads.
func WithHTTPClient(client *http.Client) Option {
	return func(m *Manager) {
		if client != nil {
			m.client = client
		}
	}
}

// WithAuditLogger sets the audit logger used for lifecycle events.
func WithAuditLogger(logger *logging.AuditLogger) Option {
	return func(m *Manager) {
		if logger != nil {
			m.logger = logger
		}
	}
}

// NewManager constructs a marketplace manager using the provided directory and
// registry source.
func NewManager(pluginsDir, registrySource string, opts ...Option) (*Manager, error) {
	pluginsDir = strings.TrimSpace(pluginsDir)
	if pluginsDir == "" {
		return nil, errors.New("plugins directory is required")
	}
	registrySource = strings.TrimSpace(registrySource)
	if registrySource == "" {
		return nil, errors.New("registry source is required")
	}

	manager := &Manager{
		pluginsDir: pluginsDir,
		allowlist:  filepath.Join(pluginsDir, "ALLOWLIST"),
		registry:   registrySource,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(manager)
	}
	if manager.logger == nil {
		manager.logger = logging.MustNewAuditLogger("plugin_marketplace")
	}
	return manager, nil
}

// Registry fetches the registry dataset.
func (m *Manager) Registry(ctx context.Context) (DatasetEnvelope, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := m.fetchRegistry(ctx)
	if err != nil {
		return DatasetEnvelope{}, err
	}
	installed, err := local.Discover(m.pluginsDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return DatasetEnvelope{}, fmt.Errorf("discover installed plugins: %w", err)
	}
	return DatasetEnvelope{
		SchemaVersion: defaultSchemaVersion,
		Dataset:       data,
		Installed:     installed,
	}, nil
}

// InstallOptions controls the installation behaviour.
type InstallOptions struct {
	Force bool
}

// Install downloads and activates the requested plugin.
func (m *Manager) Install(ctx context.Context, pluginID string, opts InstallOptions) (local.Plugin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pluginID = strings.TrimSpace(pluginID)
	if pluginID == "" {
		return local.Plugin{}, errors.New("plugin id is required")
	}

	data, err := m.fetchRegistry(ctx)
	if err != nil {
		return local.Plugin{}, err
	}

	entry, ok := data.Plugin(pluginID)
	if !ok {
		return local.Plugin{}, fmt.Errorf("plugin %s not found in registry", pluginID)
	}

	pluginDir := filepath.Join(m.pluginsDir, entry.ID)
	if _, err := os.Stat(pluginDir); err == nil && !opts.Force {
		return local.Plugin{}, fmt.Errorf("plugin %s is already installed", entry.ID)
	}

	tmpDir, err := os.MkdirTemp(m.pluginsDir, entry.ID+"-")
	if err != nil {
		return local.Plugin{}, fmt.Errorf("create plugin staging dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	manifestPath := filepath.Join(tmpDir, "manifest.json")
	if err := m.downloadFile(ctx, entry.Links["manifest"], manifestPath); err != nil {
		return local.Plugin{}, fmt.Errorf("download manifest: %w", err)
	}

	manifest, err := plugins.LoadManifest(manifestPath)
	if err != nil {
		return local.Plugin{}, err
	}

	if !strings.EqualFold(manifest.Name, entry.ID) {
		return local.Plugin{}, fmt.Errorf("registry id %s does not match manifest name %s", entry.ID, manifest.Name)
	}

	artifactDest := filepath.Clean(manifest.Artifact)
	if strings.TrimSpace(artifactDest) == "" {
		return local.Plugin{}, errors.New("manifest missing artifact path")
	}
	artifactTarget, err := safeJoin(tmpDir, artifactDest)
	if err != nil {
		return local.Plugin{}, fmt.Errorf("invalid artifact path: %w", err)
	}
	if err := m.downloadFile(ctx, entry.Links["artifact"], artifactTarget); err != nil {
		return local.Plugin{}, fmt.Errorf("download artifact: %w", err)
	}

	signatureDest := filepath.Clean(manifest.Signature.Signature)
	if strings.TrimSpace(signatureDest) == "" {
		return local.Plugin{}, errors.New("manifest missing signature reference")
	}
	signatureTarget, err := safeJoin(tmpDir, signatureDest)
	if err != nil {
		return local.Plugin{}, fmt.Errorf("invalid signature path: %w", err)
	}
	if err := m.downloadFile(ctx, entry.Links["signature"], signatureTarget); err != nil {
		return local.Plugin{}, fmt.Errorf("download signature: %w", err)
	}

	if entry.SignatureSHA256 != "" {
		hash, err := hashFile(signatureTarget)
		if err != nil {
			return local.Plugin{}, err
		}
		if !strings.EqualFold(hash, entry.SignatureSHA256) {
			return local.Plugin{}, fmt.Errorf("signature checksum mismatch: expected %s got %s", entry.SignatureSHA256, hash)
		}
	}

	if err := os.MkdirAll(filepath.Dir(pluginDir), 0o755); err != nil {
		return local.Plugin{}, fmt.Errorf("ensure plugin parent: %w", err)
	}
	if err := os.RemoveAll(pluginDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return local.Plugin{}, fmt.Errorf("clear existing plugin: %w", err)
	}
	if err := os.Rename(tmpDir, pluginDir); err != nil {
		return local.Plugin{}, fmt.Errorf("activate plugin: %w", err)
	}

	artifactPath := filepath.Join(pluginDir, artifactDest)
	artifactHash, err := integrity.HashFile(artifactPath)
	if err != nil {
		return local.Plugin{}, fmt.Errorf("hash artifact: %w", err)
	}
	artifactRel := filepath.ToSlash(filepath.Clean(filepath.Join(entry.ID, manifest.Artifact)))
	if err := m.updateAllowlist(artifactRel, artifactHash); err != nil {
		return local.Plugin{}, err
	}

	installed := local.Plugin{
		ID:             manifest.Name,
		Name:           manifest.Name,
		Version:        manifest.Version,
		Capabilities:   append([]string(nil), manifest.Capabilities...),
		Path:           pluginDir,
		ManifestPath:   filepath.Join(pluginDir, "manifest.json"),
		ArtifactPath:   artifactPath,
		ArtifactSHA256: artifactHash,
		UpdatedAt:      time.Now().UTC(),
	}
	m.emit(logging.EventPluginLoad, manifest.Name, map[string]any{
		"version": manifest.Version,
	})
	return installed, nil
}

// Remove deletes an installed plugin and clears the allowlist entry.
func (m *Manager) Remove(pluginID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pluginID = strings.TrimSpace(pluginID)
	if pluginID == "" {
		return errors.New("plugin id is required")
	}
	if strings.Contains(pluginID, "/") || strings.Contains(pluginID, "\\") || strings.Contains(pluginID, "..") {
		return errors.New("invalid plugin id")
	}

	pluginDir := filepath.Join(m.pluginsDir, pluginID)
	if err := ensureWithinBase(m.pluginsDir, pluginDir); err != nil {
		return fmt.Errorf("invalid plugin path: %w", err)
	}
	if err := os.RemoveAll(pluginDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove plugin directory: %w", err)
	}
	if err := m.removeAllowlistEntry(pluginID); err != nil {
		return err
	}
	m.emit(logging.EventPluginDisconnect, pluginID, map[string]any{
		"reason": "removed via marketplace",
	})
	return nil
}

func (m *Manager) fetchRegistry(ctx context.Context) (registry.Dataset, error) {
	if isHTTP(m.registry) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.registry, nil)
		if err != nil {
			return registry.Dataset{}, fmt.Errorf("construct registry request: %w", err)
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return registry.Dataset{}, fmt.Errorf("download registry: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			return registry.Dataset{}, fmt.Errorf("registry request returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		payload, err := io.ReadAll(resp.Body)
		if err != nil {
			return registry.Dataset{}, fmt.Errorf("read registry response: %w", err)
		}
		return registry.Decode(payload)
	}

	payload, err := os.ReadFile(m.registry)
	if err != nil {
		return registry.Dataset{}, fmt.Errorf("read registry file: %w", err)
	}
	return registry.Decode(payload)
}

func safeJoin(base, rel string) (string, error) {
	cleaned := filepath.Clean(rel)
	if cleaned == "" {
		return "", errors.New("path is empty")
	}
	if filepath.IsAbs(cleaned) {
		return "", errors.New("path must be relative")
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes base directory")
	}

	target := filepath.Join(base, cleaned)
	if err := ensureWithinBase(base, target); err != nil {
		return "", err
	}
	return target, nil
}

func ensureWithinBase(base, target string) error {
	baseClean := filepath.Clean(base)
	targetClean := filepath.Clean(target)

	rel, err := filepath.Rel(baseClean, targetClean)
	if err != nil {
		return fmt.Errorf("resolve relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("path escapes base directory")
	}
	return nil
}

func (m *Manager) downloadFile(ctx context.Context, source, target string) error {
	if strings.TrimSpace(source) == "" {
		return errors.New("download source missing")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create download target: %w", err)
	}
	if isHTTP(source) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return fmt.Errorf("construct download request: %w", err)
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return fmt.Errorf("download %s: %w", source, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			return fmt.Errorf("download %s failed with %d: %s", source, resp.StatusCode, strings.TrimSpace(string(body)))
		}
		file, err := os.Create(target)
		if err != nil {
			return fmt.Errorf("create target %s: %w", target, err)
		}
		defer file.Close()
		if _, err := io.Copy(file, resp.Body); err != nil {
			return fmt.Errorf("write %s: %w", target, err)
		}
		return nil
	}

	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read source file: %w", err)
	}
	return os.WriteFile(target, data, 0o644)
}

func (m *Manager) updateAllowlist(artifact string, hash string) error {
	if strings.TrimSpace(m.allowlist) == "" {
		return nil
	}
	entries, _ := m.loadAllowlist()
	key := filepath.ToSlash(filepath.Clean(artifact))
	entries[key] = hash
	return m.writeAllowlist(entries)
}

func (m *Manager) removeAllowlistEntry(pluginID string) error {
	if strings.TrimSpace(m.allowlist) == "" {
		return nil
	}
	entries, err := m.loadAllowlist()
	if err != nil {
		return err
	}
	prefix := filepath.ToSlash(filepath.Clean(pluginID))
	if prefix != "" {
		prefix += "/"
	}
	for key := range entries {
		if key == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(key, prefix) {
			delete(entries, key)
		}
	}
	return m.writeAllowlist(entries)
}

func (m *Manager) loadAllowlist() (map[string]string, error) {
	entries := make(map[string]string)
	file, err := os.Open(m.allowlist)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return entries, nil
		}
		return nil, fmt.Errorf("open allowlist: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid allowlist entry: %s", line)
		}
		hash := strings.ToLower(fields[0])
		if len(hash) != 64 {
			return nil, fmt.Errorf("invalid hash in allowlist: %s", line)
		}
		entries[fields[1]] = hash
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse allowlist: %w", err)
	}
	return entries, nil
}

func (m *Manager) writeAllowlist(entries map[string]string) error {
	if len(entries) == 0 {
		return os.Remove(m.allowlist)
	}

	type entry struct {
		path string
		hash string
	}
	var ordered []entry
	for path, hash := range entries {
		ordered = append(ordered, entry{path: path, hash: hash})
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].path < ordered[j].path
	})

	if err := os.MkdirAll(filepath.Dir(m.allowlist), 0o755); err != nil {
		return fmt.Errorf("prepare allowlist directory: %w", err)
	}
	file, err := os.Create(m.allowlist)
	if err != nil {
		return fmt.Errorf("write allowlist: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString("# SHA-256 allowlist for trusted plugin artifacts\n"); err != nil {
		return fmt.Errorf("write allowlist header: %w", err)
	}
	for _, item := range ordered {
		if _, err := fmt.Fprintf(file, "%s %s\n", item.hash, item.path); err != nil {
			return fmt.Errorf("write allowlist entry: %w", err)
		}
	}
	return nil
}

// DatasetEnvelope extends the registry dataset with local metadata.
type DatasetEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	registry.Dataset
	Installed []local.Plugin `json:"installed,omitempty"`
}

// PluginStatus summarises compatibility information.
type PluginStatus struct {
	ID              string `json:"id"`
	Installed       string `json:"installed,omitempty"`
	Latest          string `json:"latest"`
	Compatible      bool   `json:"compatible"`
	Compatibility   string `json:"compatibility"`
	UpdateAvailable bool   `json:"update_available"`
}

// Status computes the status entries for installed plugins.
func (d DatasetEnvelope) Status(currentVersion string) []PluginStatus {
	installedMap := make(map[string]local.Plugin, len(d.Installed))
	for _, plugin := range d.Installed {
		installedMap[plugin.ID] = plugin
	}

	var statuses []PluginStatus
	for _, entry := range d.Plugins {
		installed := installedMap[entry.ID]
		status := PluginStatus{
			ID:     entry.ID,
			Latest: entry.Version,
		}
		if installed.ID != "" {
			status.Installed = installed.Version
			status.UpdateAvailable = compareSemver(entry.Version, installed.Version) > 0
		}
		compat, ok := entry.Compatibility[currentVersion]
		if ok {
			status.Compatible = compat.Status == "compatible"
			status.Compatibility = compat.Status
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func (m *Manager) emit(event logging.EventType, plugin string, metadata map[string]any) {
	if m.logger == nil {
		return
	}
	_ = m.logger.Emit(logging.AuditEvent{
		EventType: event,
		Decision:  logging.DecisionInfo,
		PluginID:  plugin,
		Metadata:  metadata,
	})
}

func isHTTP(source string) bool {
	parsed, err := url.Parse(source)
	if err != nil {
		return false
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

func compareSemver(left, right string) int {
	if left == right {
		return 0
	}
	l := normaliseSemver(left)
	r := normaliseSemver(right)
	if semver.IsValid(l) && semver.IsValid(r) {
		return semver.Compare(l, r)
	}
	return strings.Compare(left, right)
}

func normaliseSemver(version string) string {
	trimmed := strings.TrimSpace(version)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "v") {
		return trimmed
	}
	return "v" + trimmed
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// MarshalJSON ensures the embedded dataset fields serialise correctly.
func (d DatasetEnvelope) MarshalJSON() ([]byte, error) {
	type Alias DatasetEnvelope
	return json.Marshal(struct {
		Alias
	}{Alias: Alias(d)})
}
