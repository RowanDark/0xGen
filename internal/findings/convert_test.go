package findings

import (
	"testing"
	"time"

	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
)

func TestFromProtoPopulatesDefaults(t *testing.T) {
	clock := func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) }
	meta := map[string]string{
		"target":      "https://example.com",
		"evidence":    "e",
		"detected_at": "2024-01-02T03:04:05Z",
	}
	incoming := &pb.Finding{
		Type:     "missing",
		Message:  "msg",
		Severity: pb.Severity_HIGH,
		Metadata: meta,
	}

	finding, err := fromProtoWithClock("plugin-1", incoming, clock)
	if err != nil {
		t.Fatalf("fromProto: %v", err)
	}
	if finding.ID == "" {
		t.Fatal("expected id to be populated")
	}
	if finding.Plugin != "plugin-1" {
		t.Fatalf("unexpected plugin: %s", finding.Plugin)
	}
	if finding.Target != "https://example.com" {
		t.Fatalf("unexpected target: %s", finding.Target)
	}
	if finding.Evidence != "e" {
		t.Fatalf("unexpected evidence: %s", finding.Evidence)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("unexpected severity: %s", finding.Severity)
	}
	if !finding.DetectedAt.Equal(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("unexpected detected_at: %v", finding.DetectedAt.Time())
	}
}

func TestFromProtoRejectsBadTimestamp(t *testing.T) {
	incoming := &pb.Finding{Metadata: map[string]string{"detected_at": "not-a-timestamp"}}
	if _, err := FromProto("p", incoming); err == nil {
		t.Fatal("expected error for bad timestamp")
	}
}
