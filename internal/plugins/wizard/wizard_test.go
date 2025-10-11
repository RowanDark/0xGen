package wizard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/logging"
)

type fakeRegistrar struct {
	registerCalls   []registration
	unregisterCalls []string
}

type registration struct {
	plugin string
	caps   []string
}

func (f *fakeRegistrar) Register(pluginID string, capabilities []string) {
	caps := make([]string, len(capabilities))
	copy(caps, capabilities)
	f.registerCalls = append(f.registerCalls, registration{plugin: pluginID, caps: caps})
}

func (f *fakeRegistrar) Unregister(pluginID string) {
	f.unregisterCalls = append(f.unregisterCalls, pluginID)
}

func TestDescribeCapabilities(t *testing.T) {
	summaries, err := DescribeCapabilities([]string{"cap_emit_findings", "cap_flow_inspect_raw"})
	if err != nil {
		t.Fatalf("DescribeCapabilities returned error: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}
	if !summaries[0].HighRisk || summaries[0].Capability != "CAP_FLOW_INSPECT_RAW" {
		t.Fatalf("expected high-risk capability to be first, got %+v", summaries[0])
	}
	if summaries[1].Capability != "CAP_EMIT_FINDINGS" {
		t.Fatalf("expected CAP_EMIT_FINDINGS second, got %s", summaries[1].Capability)
	}
}

func TestBuildAccessMatrix(t *testing.T) {
	matrix := BuildAccessMatrix(map[string]bool{
		"CAP_FLOW_INSPECT":     true,
		"CAP_EMIT_FINDINGS":    true,
		"CAP_STORAGE":          false,
		"CAP_HTTP_ACTIVE":      true,
		"CAP_FLOW_INSPECT_RAW": false,
	})
	if len(matrix) != 4 {
		t.Fatalf("expected 4 matrix rows, got %d", len(matrix))
	}
	http := matrix[0]
	if !http.SanitizedAllowed || http.RawAllowed {
		t.Fatalf("expected sanitized-only HTTP access, got %+v", http)
	}
	if matrix[2].RawAllowed {
		t.Fatalf("storage should remain blocked without CAP_STORAGE")
	}
	if !matrix[3].RawAllowed {
		t.Fatalf("HTTP egress should be permitted when CAP_HTTP_ACTIVE granted")
	}
}

func TestGrantStoreLifecycle(t *testing.T) {
	var buf bytes.Buffer
	audit, err := logging.NewAuditLogger("wizard", logging.WithWriter(&buf), logging.WithoutStdout())
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	registrar := &fakeRegistrar{}
	now := time.Date(2024, time.January, 15, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	idSeq := 0
	idGen := func() string {
		idSeq++
		return fmt.Sprintf("audit-%02d", idSeq)
	}
	store, err := NewGrantStore(audit, registrar, WithClock(clock), WithIDGenerator(idGen))
	if err != nil {
		t.Fatalf("NewGrantStore: %v", err)
	}

	grant, err := store.Install("seer", []string{"CAP_EMIT_FINDINGS", "cap_report"}, "alice")
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	if len(grant.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(grant.Capabilities))
	}
	if got := registrar.registerCalls; len(got) != 1 || got[0].plugin != "seer" {
		t.Fatalf("expected registrar register call, got %#v", got)
	}

	revoked, err := store.Revoke("seer", "cap_report", "no longer required")
	if err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	if len(revoked.Capabilities) != 1 || revoked.Capabilities[0] != "CAP_EMIT_FINDINGS" {
		t.Fatalf("expected single capability remaining, got %+v", revoked.Capabilities)
	}
	if got := registrar.registerCalls; len(got) != 2 || len(got[1].caps) != 1 {
		t.Fatalf("expected second register call with remaining cap, got %#v", got)
	}

	if err := store.RevokeAll("seer", "operator request"); err != nil {
		t.Fatalf("RevokeAll returned error: %v", err)
	}
	if len(registrar.unregisterCalls) != 1 || registrar.unregisterCalls[0] != "seer" {
		t.Fatalf("expected unregister for seer, got %#v", registrar.unregisterCalls)
	}
	if grants := store.List(); len(grants) != 0 {
		t.Fatalf("expected all grants cleared, got %#v", grants)
	}

	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	var events []logging.AuditEvent
	for {
		var evt logging.AuditEvent
		if err := dec.Decode(&evt); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("decode audit: %v", err)
		}
		events = append(events, evt)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 audit events, got %d", len(events))
	}
	if events[0].EventType != logging.EventCapabilityGrant {
		t.Fatalf("expected first event to be grant, got %s", events[0].EventType)
	}
	if events[1].EventType != logging.EventCapabilityDenied {
		t.Fatalf("expected second event to be denial, got %s", events[1].EventType)
	}
	if events[1].Metadata["revoked_capability"] != "CAP_REPORT" {
		t.Fatalf("expected CAP_REPORT revocation, got %+v", events[1].Metadata)
	}
	if events[2].Metadata["revoked_all"] != true {
		t.Fatalf("expected final event to record revoke all, got %+v", events[2].Metadata)
	}
}
