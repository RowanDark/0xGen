package findings

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Severity captures the allowed severity values for findings persisted by the
// host. The values are intentionally normalised to uppercase so JSON encoding
// is stable and easy to validate.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

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
	parsed := Severity(strings.ToUpper(strings.TrimSpace(raw)))
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

// Finding represents a single issue reported by a plugin.
type Finding struct {
	ID         string            `json:"id"`
	Plugin     string            `json:"plugin"`
	Type       string            `json:"type"`
	Message    string            `json:"message"`
	Target     string            `json:"target,omitempty"`
	Evidence   string            `json:"evidence,omitempty"`
	Severity   Severity          `json:"severity"`
	DetectedAt time.Time         `json:"detected_at"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Validate performs sanity checks ensuring the struct complies with the
// contract codified in specs/finding.schema.json.
func (f Finding) Validate() error {
	if strings.TrimSpace(f.ID) == "" {
		return errors.New("finding id is required")
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
		return errors.New("detected_at is required")
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
	return f.DetectedAt.UTC()
}
