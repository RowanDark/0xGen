package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RowanDark/Glyph/internal/logging"
	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServerGetSecret(t *testing.T) {
	mgr := NewManager(map[string]map[string]string{
		"seer": {"api_token": "top-secret"},
	})
	token, _, err := mgr.Issue("seer", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	logger, buf := newAuditLogger(t)
	srv := NewServer(mgr, WithServerAuditLogger(logger))

	resp, err := srv.GetSecret(context.Background(), &pb.SecretAccessRequest{
		PluginName: "seer",
		Token:      token,
		SecretName: "API_TOKEN",
	})
	if err != nil {
		t.Fatalf("GetSecret returned error: %v", err)
	}
	if resp.GetValue() != "top-secret" {
		t.Fatalf("unexpected secret value %q", resp.GetValue())
	}
	if strings.Contains(buf.String(), "top-secret") {
		t.Fatalf("secret leaked to audit log: %s", buf.String())
	}
	event := decodeAuditEvent(t, buf.Bytes())
	if event.EventType != logging.EventSecretsAccess {
		t.Fatalf("expected secrets access event, got %q", event.EventType)
	}
	if event.Decision != logging.DecisionAllow {
		t.Fatalf("expected allow decision, got %q", event.Decision)
	}
}

func TestServerDeniesUnrequestedSecret(t *testing.T) {
	mgr := NewManager(map[string]map[string]string{
		"seer": {"api_token": "top-secret"},
	})
	token, _, err := mgr.Issue("seer", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	logger, buf := newAuditLogger(t)
	srv := NewServer(mgr, WithServerAuditLogger(logger))

	_, err = srv.GetSecret(context.Background(), &pb.SecretAccessRequest{
		PluginName: "seer",
		Token:      token,
		SecretName: "DB_PASSWORD",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected permission denied, got %v", err)
	}
	events := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(events) == 0 {
		t.Fatalf("expected audit event for denial")
	}
	event := decodeAuditEvent(t, events[len(events)-1])
	if event.EventType != logging.EventSecretsDenied {
		t.Fatalf("expected secrets denied event, got %q", event.EventType)
	}
	if event.Decision != logging.DecisionDeny {
		t.Fatalf("expected deny decision, got %q", event.Decision)
	}
}

func newAuditLogger(t *testing.T) (*logging.AuditLogger, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	logger, err := logging.NewAuditLogger("test", logging.WithoutStdout(), logging.WithWriter(buf))
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}
	return logger, buf
}

func decodeAuditEvent(t *testing.T, data []byte) logging.AuditEvent {
	t.Helper()
	var event logging.AuditEvent
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatalf("decode audit event: %v", err)
	}
	return event
}
