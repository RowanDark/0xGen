package osintwell

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	defaultOutputDir   = "/out"
	assetsFilename     = "assets.jsonl"
	amassToolName      = "amass"
	defaultToolLabel   = "amass-passive"
	scannerBufferLimit = 1024 * 1024
)

const (
	// DefaultToolLabel identifies the passive Amass source when writing assets.
	DefaultToolLabel = defaultToolLabel
)

var (
	// DefaultOutputPath is where normalised assets are persisted by default.
	DefaultOutputPath = filepath.Join(defaultOutputDir, assetsFilename)
)

func init() {
	if custom := strings.TrimSpace(os.Getenv("GLYPH_OUT")); custom != "" {
		DefaultOutputPath = filepath.Join(custom, assetsFilename)
	}
}

// Config controls how the Amass wrapper executes.
type Config struct {
	Domain     string
	OutputPath string
	Binary     string
	ExtraArgs  []string
	ToolLabel  string
}

// Run executes Amass with the supplied configuration and writes normalised assets to disk.
func Run(ctx context.Context, cfg Config) error {
	cfg = cfg.withDefaults()
	if strings.TrimSpace(cfg.Domain) == "" {
		return errors.New("domain must be provided")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	args := []string{"enum", "-passive", "-d", cfg.Domain}
	if len(cfg.ExtraArgs) > 0 {
		args = append(args, cfg.ExtraArgs...)
	}
	args = append(args, "-json", "-")

	cmd := exec.CommandContext(ctx, cfg.Binary, args...) // #nosec G204 -- runtime configuration controls the binary.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("amass stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start amass: %w", err)
	}

	records, normErr := Normalize(stdout, time.Now, cfg.ToolLabel)
	waitErr := cmd.Wait()
	if normErr != nil {
		return fmt.Errorf("normalize amass output: %w", normErr)
	}
	if waitErr != nil {
		return fmt.Errorf("amass execution failed: %w", waitErr)
	}

	if err := writeRecords(cfg.OutputPath, records); err != nil {
		return fmt.Errorf("write assets: %w", err)
	}
	return nil
}

func (cfg Config) withDefaults() Config {
	if strings.TrimSpace(cfg.OutputPath) == "" {
		cfg.OutputPath = DefaultOutputPath
	}
	if strings.TrimSpace(cfg.Binary) == "" {
		cfg.Binary = amassToolName
	}
	if strings.TrimSpace(cfg.ToolLabel) == "" {
		cfg.ToolLabel = defaultToolLabel
	}
	return cfg
}

type amassEvent struct {
	Timestamp string         `json:"timestamp"`
	Name      string         `json:"name"`
	Domain    string         `json:"domain"`
	Tag       string         `json:"tag"`
	Sources   []string       `json:"sources"`
	Addresses []amassAddress `json:"addresses"`
}

type amassAddress struct {
	IP string `json:"ip"`
}

// Record represents a normalised asset entry.
type Record struct {
	Name      string
	Domain    string
	Addresses []string
	Sources   []string
	Tags      []string
	FirstSeen time.Time
	Tool      string
}

// Normalize parses Amass JSONL output and returns a slice of aggregated asset records.
func Normalize(r io.Reader, now func() time.Time, toolLabel string) ([]Record, error) {
	if now == nil {
		now = time.Now
	}
	if strings.TrimSpace(toolLabel) == "" {
		toolLabel = defaultToolLabel
	}

	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, scannerBufferLimit)

	type aggregate struct {
		Name      string
		Domain    string
		Addresses map[string]struct{}
		Sources   map[string]struct{}
		Tags      map[string]struct{}
		FirstSeen time.Time
	}

	aggregates := make(map[string]*aggregate)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event amassEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("decode amass event: %w", err)
		}
		name := strings.TrimSpace(event.Name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		agg, ok := aggregates[key]
		if !ok {
			agg = &aggregate{
				Name:      name,
				Domain:    strings.TrimSpace(event.Domain),
				Addresses: make(map[string]struct{}),
				Sources:   make(map[string]struct{}),
				Tags:      make(map[string]struct{}),
			}
			aggregates[key] = agg
		}
		if agg.Domain == "" {
			agg.Domain = strings.TrimSpace(event.Domain)
		}
		ts := parseTimestamp(event.Timestamp, now())
		if agg.FirstSeen.IsZero() || ts.Before(agg.FirstSeen) {
			agg.FirstSeen = ts
		}
		for _, addr := range event.Addresses {
			ip := strings.TrimSpace(addr.IP)
			if ip != "" {
				agg.Addresses[ip] = struct{}{}
			}
		}
		for _, source := range event.Sources {
			trimmed := strings.TrimSpace(source)
			if trimmed != "" {
				agg.Sources[trimmed] = struct{}{}
			}
		}
		if tag := strings.TrimSpace(event.Tag); tag != "" {
			agg.Tags[strings.ToLower(tag)] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read amass output: %w", err)
	}

	records := make([]Record, 0, len(aggregates))
	for _, agg := range aggregates {
		record := Record{
			Name:      agg.Name,
			Domain:    agg.Domain,
			Addresses: setToSortedSlice(agg.Addresses),
			Sources:   setToSortedSlice(agg.Sources),
			Tags:      setToSortedSlice(agg.Tags),
			FirstSeen: agg.FirstSeen,
			Tool:      toolLabel,
		}
		if record.FirstSeen.IsZero() {
			record.FirstSeen = now()
		}
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Name == records[j].Name {
			return records[i].Domain < records[j].Domain
		}
		return records[i].Name < records[j].Name
	})
	return records, nil
}

func parseTimestamp(value string, fallback time.Time) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	if ts, err := time.Parse(time.RFC3339, value); err == nil {
		return ts.UTC()
	}
	return fallback
}

func setToSortedSlice(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func writeRecords(path string, records []Record) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create assets directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("open assets file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	for _, record := range records {
		payload := struct {
			Name      string   `json:"name"`
			Domain    string   `json:"domain,omitempty"`
			Addresses []string `json:"addresses,omitempty"`
			Sources   []string `json:"sources,omitempty"`
			Tags      []string `json:"tags,omitempty"`
			FirstSeen string   `json:"first_seen"`
			Tool      string   `json:"tool"`
		}{
			Name:      record.Name,
			Domain:    record.Domain,
			Addresses: record.Addresses,
			Sources:   record.Sources,
			Tags:      record.Tags,
			FirstSeen: record.FirstSeen.UTC().Format(time.RFC3339),
			Tool:      record.Tool,
		}
		if err := encoder.Encode(payload); err != nil {
			return fmt.Errorf("encode asset: %w", err)
		}
	}
	return nil
}
