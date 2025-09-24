package findings

import (
	"errors"
	"fmt"
	"strings"
	"time"

	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
)

const (
	metadataID         = "id"
	metadataTarget     = "target"
	metadataEvidence   = "evidence"
	metadataDetectedAt = "detected_at"
)

// FromProto converts a protobuf Finding emitted by a plugin into the internal
// representation persisted by glyphd.
func FromProto(pluginID string, incoming *pb.Finding) (Finding, error) {
	return fromProtoWithClock(pluginID, incoming, time.Now)
}

func fromProtoWithClock(pluginID string, incoming *pb.Finding, clock func() time.Time) (Finding, error) {
	if incoming == nil {
		return Finding{}, errors.New("incoming finding is nil")
	}
	if pluginID = strings.TrimSpace(pluginID); pluginID == "" {
		return Finding{}, errors.New("plugin id is required")
	}

	metadata := incoming.GetMetadata()
	if metadata == nil {
		metadata = map[string]string{}
	}

	id := strings.ToUpper(strings.TrimSpace(metadata[metadataID]))
	if id == "" {
		id = NewID()
	}

	detectedAt := clock().UTC()
	if ts := strings.TrimSpace(metadata[metadataDetectedAt]); ts != "" {
		parsed, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return Finding{}, fmt.Errorf("invalid detected_at timestamp: %w", err)
		}
		detectedAt = parsed.UTC()
	}

	cleanMeta := make(map[string]string, len(metadata))
	for k, v := range metadata {
		switch k {
		case metadataID, metadataTarget, metadataEvidence, metadataDetectedAt:
			continue
		default:
			cleanMeta[k] = v
		}
	}
	if len(cleanMeta) == 0 {
		cleanMeta = nil
	}

	f := Finding{
		Version:    SchemaVersion,
		ID:         id,
		Plugin:     pluginID,
		Type:       strings.TrimSpace(incoming.GetType()),
		Message:    strings.TrimSpace(incoming.GetMessage()),
		Target:     strings.TrimSpace(metadata[metadataTarget]),
		Evidence:   metadata[metadataEvidence],
		Severity:   severityFromProto(incoming.GetSeverity()),
		DetectedAt: NewTimestamp(detectedAt),
		Metadata:   cleanMeta,
	}

	if f.Evidence == "" {
		f.Evidence = f.Message
	}

	if err := f.Validate(); err != nil {
		return Finding{}, err
	}

	return f, nil
}

func severityFromProto(sev pb.Severity) Severity {
	switch sev {
	case pb.Severity_CRITICAL:
		return SeverityCritical
	case pb.Severity_HIGH:
		return SeverityHigh
	case pb.Severity_MEDIUM:
		return SeverityMedium
	case pb.Severity_LOW:
		return SeverityLow
	case pb.Severity_INFO:
		return SeverityInfo
	default:
		return SeverityInfo
	}
}
