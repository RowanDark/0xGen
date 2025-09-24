package findings

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Severity captures the allowed severity values for findings persisted by the
// host. The values are normalised to lowercase short codes for stable JSON
// encoding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "med"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "crit"
)

// SchemaVersion captures the canonical findings schema version persisted to disk.
const SchemaVersion = "0.2"

var severitySet = map[Severity]struct{}{
	SeverityInfo:     {},
	SeverityLow:      {},
	SeverityMedium:   {},
	SeverityHigh:     {},
	SeverityCritical: {},
}

// MarshalJSON ensures severities are always emitted as quoted strings.
func (s Severity) MarshalJSON() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(string(s))
}

// UnmarshalJSON performs strict validation so we catch typos during testing and
// when loading persisted findings.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	parsed := Severity(strings.ToLower(strings.TrimSpace(raw)))
	if err := parsed.validate(); err != nil {
		return err
	}
	*s = parsed
	return nil
}

func (s Severity) validate() error {
	if _, ok := severitySet[s]; !ok {
		return fmt.Errorf("invalid severity: %q", s)
	}
	return nil
}

// Timestamp enforces RFC3339 timestamps when encoding findings to disk.
type Timestamp time.Time

// NewTimestamp normalises the input time before persisting it.
func NewTimestamp(t time.Time) Timestamp {
	if t.IsZero() {
		return Timestamp{}
	}
	return Timestamp(t.UTC().Truncate(time.Second))
}

// Time exposes the underlying time value.
func (t Timestamp) Time() time.Time {
	return time.Time(t)
}

// IsZero reports whether the timestamp has been initialised.
func (t Timestamp) IsZero() bool {
	return time.Time(t).IsZero()
}

// Equal compares the timestamp to the provided time value.
func (t Timestamp) Equal(other time.Time) bool {
	return time.Time(t).Equal(other)
}

// MarshalJSON renders the timestamp using time.RFC3339. Zero values encode as
// an empty string so Validate can flag missing timestamps explicitly.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return json.Marshal("")
	}
	return json.Marshal(tt.UTC().Format(time.RFC3339))
}

// UnmarshalJSON enforces RFC3339 timestamps when reading persisted findings.
func (t *Timestamp) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		*t = Timestamp{}
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return fmt.Errorf("invalid ts timestamp: %w", err)
	}
	*t = NewTimestamp(parsed)
	return nil
}

// NewID generates a new ULID suitable for persisting as a finding identifier.
func NewID() string {
	buf := make([]byte, 16)
	ts := uint64(time.Now().UTC().UnixMilli())
	for i := 5; i >= 0; i-- {
		buf[i] = byte(ts & 0xFF)
		ts >>= 8
	}
	if _, err := io.ReadFull(rand.Reader, buf[6:]); err != nil {
		// Fall back to deterministic bytes derived from the current time to
		// avoid panicking in restricted environments.
		nano := uint64(time.Now().UTC().UnixNano())
		for i := 6; i < len(buf); i++ {
			buf[i] = byte(nano & 0xFF)
			nano >>= 8
		}
	}
	return crockford.EncodeToString(buf)
}

// Finding represents a single issue reported by a plugin.
type Finding struct {
	Version    string            `json:"version"`
	ID         string            `json:"id"`
	Plugin     string            `json:"plugin"`
	Type       string            `json:"type"`
	Message    string            `json:"message"`
	Target     string            `json:"target,omitempty"`
	Evidence   string            `json:"evidence,omitempty"`
	Severity   Severity          `json:"severity"`
	DetectedAt Timestamp         `json:"ts"`
	Metadata   map[string]string `json:"meta,omitempty"`
}

// Validate performs sanity checks ensuring the struct complies with the
// contract codified in specs/finding.md.
func (f Finding) Validate() error {
	if strings.TrimSpace(f.Version) == "" {
		return errors.New("version is required")
	}
	if strings.TrimSpace(f.Version) != SchemaVersion {
		return fmt.Errorf("unsupported version %q", f.Version)
	}
	if strings.TrimSpace(f.ID) == "" {
		return errors.New("finding id is required")
	}
	if _, err := decodeULID(strings.TrimSpace(f.ID)); err != nil {
		return fmt.Errorf("invalid id: %w", err)
	}
	if strings.TrimSpace(f.Plugin) == "" {
		return errors.New("plugin is required")
	}
	if strings.TrimSpace(f.Type) == "" {
		return errors.New("type is required")
	}
	if strings.TrimSpace(f.Message) == "" {
		return errors.New("message is required")
	}
	if err := f.Severity.validate(); err != nil {
		return err
	}
	if f.DetectedAt.IsZero() {
		return errors.New("ts is required")
	}
	return nil
}

// Clone returns a deep copy of the finding to avoid accidental mutation when
// broadcasting to subscribers.
func (f Finding) Clone() Finding {
	copy := f
	if len(f.Metadata) > 0 {
		copy.Metadata = make(map[string]string, len(f.Metadata))
		for k, v := range f.Metadata {
			copy.Metadata[k] = v
		}
	}
	return copy
}

// Timestamp returns the detection timestamp in UTC to simplify reporting code.
func (f Finding) Timestamp() time.Time {
	return f.DetectedAt.Time().UTC()
}

var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

func decodeULID(id string) ([]byte, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("ulid is empty")
	}
	if len(id) != 26 {
		return nil, fmt.Errorf("ulid must be 26 characters, got %d", len(id))
	}
	upper := strings.ToUpper(id)
	if upper != id {
		return nil, errors.New("ulid must be upper-case")
	}
	decoded, err := crockford.DecodeString(upper)
	if err != nil {
		return nil, fmt.Errorf("decode ulid: %w", err)
	}
	if len(decoded) != 16 {
		return nil, fmt.Errorf("decoded ulid length %d", len(decoded))
	}
	return decoded, nil
}
