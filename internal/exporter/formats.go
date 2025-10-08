package exporter

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/RowanDark/Glyph/internal/cases"
	"github.com/RowanDark/Glyph/internal/findings"
)

// Request captures the data set that exporters operate on.
type Request struct {
	Cases     []cases.Case
	Findings  []findings.Finding
	Telemetry Telemetry
}

// EncodeFunc renders the provided dataset into an exportable representation.
type EncodeFunc func(Request) ([]byte, error)

// FormatSpec describes an exporter implementation registered at runtime.
type FormatSpec struct {
	Format          Format
	Description     string
	DefaultFilename string
	Encode          EncodeFunc
}

var (
	registryMu sync.RWMutex
	registry   = map[Format]FormatSpec{}
	baseOutput = defaultOutputDir
)

// RegisterFormat adds a new exporter implementation to the registry.
func RegisterFormat(spec FormatSpec) error {
	name := Format(strings.ToLower(strings.TrimSpace(string(spec.Format))))
	if name == "" {
		return fmt.Errorf("exporter format name is required")
	}
	if spec.Encode == nil {
		return fmt.Errorf("exporter %q is missing an encoder", name)
	}

	spec.Format = name

	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[name]; exists {
		return fmt.Errorf("export format %q already registered", name)
	}
	registry[name] = spec
	return nil
}

// MustRegisterFormat adds an exporter to the registry and panics if registration fails.
func MustRegisterFormat(spec FormatSpec) {
	if err := RegisterFormat(spec); err != nil {
		panic(err)
	}
}

// ParseFormat validates the provided format string.
func ParseFormat(raw string) (Format, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", fmt.Errorf("unsupported format %q", raw)
	}

	registryMu.RLock()
	defer registryMu.RUnlock()

	format := Format(trimmed)
	if _, exists := registry[format]; exists {
		return format, nil
	}

	names := make([]string, 0, len(registry))
	for key := range registry {
		names = append(names, string(key))
	}
	sort.Strings(names)

	return "", fmt.Errorf("unsupported format %q (available: %s)", raw, strings.Join(names, ", "))
}

// Encode resolves the requested format and renders the dataset using the registered implementation.
func Encode(format Format, req Request) ([]byte, error) {
	registryMu.RLock()
	spec, ok := registry[format]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unregistered export format: %s", format)
	}
	return spec.Encode(req)
}

// DefaultPath returns the default output location for the provided format if defined.
func DefaultPath(format Format) (string, error) {
	registryMu.RLock()
	spec, ok := registry[format]
	registryMu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unregistered export format: %s", format)
	}
	filename := strings.TrimSpace(spec.DefaultFilename)
	if filename == "" {
		return "", fmt.Errorf("format %q does not define a default output path", format)
	}
	return filepath.Join(baseOutput, filename), nil
}

// Formats returns the registered exporters sorted by format name.
func Formats() []FormatSpec {
	registryMu.RLock()
	defer registryMu.RUnlock()

	specs := make([]FormatSpec, 0, len(registry))
	for _, spec := range registry {
		specs = append(specs, spec)
	}
	sort.Slice(specs, func(i, j int) bool {
		return specs[i].Format < specs[j].Format
	})
	return specs
}

func setBaseOutput(dir string) {
	registryMu.Lock()
	baseOutput = dir
	registryMu.Unlock()
}
