package history

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/RowanDark/Glyph/internal/proxy"
)

const defaultHistoryFilename = "proxy_history.jsonl"

// Entry represents a single history record indexed from the JSONL file.
type Entry struct {
	ID     string
	Record proxy.HistoryEntry
}

type indexedEntry struct {
	id            string
	record        proxy.HistoryEntry
	hostLower     string
	pathLower     string
	methodLower   string
	protocolLower string
	urlLower      string
	statusCode    int
	matchedLower  []string
}

// Index provides in-memory search capabilities over persisted history entries.
type Index struct {
	entries   []indexedEntry
	positions map[string]int
}

// DefaultPath returns the default location of the proxy history log, honouring GLYPH_OUT.
func DefaultPath() string {
	dir := strings.TrimSpace(os.Getenv("GLYPH_OUT"))
	if dir == "" {
		dir = "/out"
	}
	return filepath.Join(dir, defaultHistoryFilename)
}

// Load builds an index by parsing the given history JSONL file.
func Load(path string) (*Index, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open history: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Allow large payloads to be indexed without failing.
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	idx := &Index{
		positions: make(map[string]int),
	}
	line := 0
	id := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var record proxy.HistoryEntry
		if err := json.Unmarshal([]byte(raw), &record); err != nil {
			return nil, fmt.Errorf("decode history entry on line %d: %w", line, err)
		}
		id++
		indexed := indexedEntry{
			id:            strconv.Itoa(id),
			record:        record,
			methodLower:   strings.ToLower(record.Method),
			protocolLower: strings.ToLower(record.Protocol),
			urlLower:      strings.ToLower(record.URL),
			statusCode:    record.StatusCode,
		}
		if u, err := url.Parse(record.URL); err == nil {
			indexed.hostLower = strings.ToLower(u.Host)
			indexed.pathLower = strings.ToLower(u.Path)
		}
		if len(record.MatchedRules) > 0 {
			indexed.matchedLower = make([]string, len(record.MatchedRules))
			for i, rule := range record.MatchedRules {
				indexed.matchedLower[i] = strings.ToLower(rule)
			}
		}
		idx.positions[indexed.id] = len(idx.entries)
		idx.entries = append(idx.entries, indexed)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan history: %w", err)
	}
	return idx, nil
}

// Entries returns a copy of all indexed entries in chronological order.
func (i *Index) Entries() []Entry {
	if i == nil {
		return nil
	}
	out := make([]Entry, len(i.entries))
	for idx, entry := range i.entries {
		out[idx] = entry.entry()
	}
	return out
}

// Entry retrieves a specific history record by ID.
func (i *Index) Entry(id string) (Entry, bool) {
	if i == nil {
		return Entry{}, false
	}
	pos, ok := i.positions[id]
	if !ok {
		return Entry{}, false
	}
	return i.entries[pos].entry(), true
}

type predicate func(*indexedEntry) bool

// Search returns every entry matching the provided query string.
//
// The query language accepts whitespace-separated terms in the form key:value.
// Supported keys include host, method, protocol, path, url, status, and rule.
func (i *Index) Search(rawQuery string) ([]Entry, error) {
	if i == nil {
		return nil, fmt.Errorf("index not initialised")
	}
	predicates, err := parseQuery(rawQuery)
	if err != nil {
		return nil, err
	}
	if len(predicates) == 0 {
		results := make([]Entry, len(i.entries))
		for idx, entry := range i.entries {
			results[idx] = entry.entry()
		}
		return results, nil
	}
	var results []Entry
	for idx := range i.entries {
		entry := &i.entries[idx]
		match := true
		for _, predicate := range predicates {
			if !predicate(entry) {
				match = false
				break
			}
		}
		if match {
			results = append(results, entry.entry())
		}
	}
	return results, nil
}

func parseQuery(input string) ([]predicate, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, nil
	}
	tokens := strings.Fields(trimmed)
	predicates := make([]predicate, 0, len(tokens))
	for _, token := range tokens {
		parts := strings.SplitN(token, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid query token %q (expected key:value)", token)
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if value == "" {
			return nil, fmt.Errorf("query term %q missing value", key)
		}
		switch key {
		case "host":
			host := strings.ToLower(value)
			predicates = append(predicates, func(entry *indexedEntry) bool {
				return entry.hostLower != "" && strings.Contains(entry.hostLower, host)
			})
		case "method":
			method := strings.ToLower(value)
			predicates = append(predicates, func(entry *indexedEntry) bool {
				return entry.methodLower == method
			})
		case "protocol":
			protocol := strings.ToLower(value)
			predicates = append(predicates, func(entry *indexedEntry) bool {
				return entry.protocolLower == protocol
			})
		case "path":
			path := strings.ToLower(value)
			predicates = append(predicates, func(entry *indexedEntry) bool {
				return entry.pathLower != "" && strings.Contains(entry.pathLower, path)
			})
		case "url":
			urlValue := strings.ToLower(value)
			predicates = append(predicates, func(entry *indexedEntry) bool {
				return strings.Contains(entry.urlLower, urlValue)
			})
		case "status":
			status, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid status %q", value)
			}
			predicates = append(predicates, func(entry *indexedEntry) bool {
				return entry.statusCode == status
			})
		case "rule":
			rule := strings.ToLower(value)
			predicates = append(predicates, func(entry *indexedEntry) bool {
				for _, candidate := range entry.matchedLower {
					if candidate == rule {
						return true
					}
				}
				return false
			})
		default:
			return nil, fmt.Errorf("unsupported query field %q", key)
		}
	}
	return predicates, nil
}

// Append persists a new history entry to the JSONL log.
func Append(path string, entry proxy.HistoryEntry) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("history path must not be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create history directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open history file: %w", err)
	}
	defer file.Close()
	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode history entry: %w", err)
	}
	payload = append(payload, '\n')
	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("write history entry: %w", err)
	}
	return nil
}

func cloneHistory(in proxy.HistoryEntry) proxy.HistoryEntry {
	out := in
	if in.RequestHeaders != nil {
		out.RequestHeaders = cloneHeaderMap(in.RequestHeaders)
	}
	if in.ResponseHeaders != nil {
		out.ResponseHeaders = cloneHeaderMap(in.ResponseHeaders)
	}
	if len(in.MatchedRules) > 0 {
		out.MatchedRules = append([]string(nil), in.MatchedRules...)
	}
	return out
}

func cloneHeaderMap(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func (e indexedEntry) entry() Entry {
	return Entry{
		ID:     e.id,
		Record: cloneHistory(e.record),
	}
}
