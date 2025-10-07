package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/logging"
	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServerGetSecret(t *testing.T) {
	mgr := NewManager(map[string]map[string]string{
		"seer": {"api_token": "top-secret"},
	})
	token, _, err := mgr.Issue("seer", "scope-1", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	logger, buf := newTestAuditLogger(t)
	srv := NewServer(mgr, WithServerAuditLogger(logger))

	resp, err := srv.GetSecret(context.Background(), &pb.SecretAccessRequest{
		PluginName: "seer",
		Token:      token,
		ScopeId:    "scope-1",
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
	token, _, err := mgr.Issue("seer", "scope-1", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	logger, buf := newTestAuditLogger(t)
	srv := NewServer(mgr, WithServerAuditLogger(logger))

	_, err = srv.GetSecret(context.Background(), &pb.SecretAccessRequest{
		PluginName: "seer",
		Token:      token,
		ScopeId:    "scope-1",
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

func TestServerDeniesMismatchedScope(t *testing.T) {
	mgr := NewManager(map[string]map[string]string{
		"seer": {"api_token": "top-secret"},
	})
	token, _, err := mgr.Issue("seer", "scope-a", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	logger, buf := newTestAuditLogger(t)
	srv := NewServer(mgr, WithServerAuditLogger(logger))

	_, err = srv.GetSecret(context.Background(), &pb.SecretAccessRequest{
		PluginName: "seer",
		Token:      token,
		ScopeId:    "scope-b",
		SecretName: "API_TOKEN",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected permission denied, got %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("secrets_denied")) {
		t.Fatalf("expected denial to be audited")
	}
}

func TestServerDeniesExpiredToken(t *testing.T) {
	current := time.Unix(0, 0).UTC()
	clock := func() time.Time { return current }
	managerLogger, managerBuf := newTestAuditLogger(t)
	mgr := NewManager(map[string]map[string]string{
		"seer": {"api_token": "top-secret"},
	}, WithClock(clock), WithTTL(time.Minute), WithAuditLogger(managerLogger))
	token, _, err := mgr.Issue("seer", "scope-1", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	serverLogger, serverBuf := newTestAuditLogger(t)
	srv := NewServer(mgr, WithServerAuditLogger(serverLogger))

	// Initial access succeeds to ensure baseline behaviour.
	if _, err := srv.GetSecret(context.Background(), &pb.SecretAccessRequest{
		PluginName: "seer",
		Token:      token,
		ScopeId:    "scope-1",
		SecretName: "API_TOKEN",
	}); err != nil {
		t.Fatalf("GetSecret before expiry returned error: %v", err)
	}

	current = current.Add(2 * time.Minute)
	_, err = srv.GetSecret(context.Background(), &pb.SecretAccessRequest{
		PluginName: "seer",
		Token:      token,
		ScopeId:    "scope-1",
		SecretName: "API_TOKEN",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected permission denied for expired token, got %v", err)
	}
	if !bytes.Contains(serverBuf.Bytes(), []byte("secrets_denied")) {
		t.Fatalf("expected denial to be audited")
	}
	if !bytes.Contains(managerBuf.Bytes(), []byte(string(logging.EventSecretsTokenExpiry))) {
		t.Fatalf("expected expiry to be logged in manager audit log")
	}
}

func TestServerDeniesRevokedToken(t *testing.T) {
	managerLogger, managerBuf := newTestAuditLogger(t)
	mgr := NewManager(map[string]map[string]string{
		"seer": {"api_token": "top-secret"},
	}, WithAuditLogger(managerLogger))
	token, _, err := mgr.Issue("seer", "scope-1", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if err := mgr.Revoke(token); err != nil {
		t.Fatalf("revoke token: %v", err)
	}
	serverLogger, serverBuf := newTestAuditLogger(t)
	srv := NewServer(mgr, WithServerAuditLogger(serverLogger))

	_, err = srv.GetSecret(context.Background(), &pb.SecretAccessRequest{
		PluginName: "seer",
		Token:      token,
		ScopeId:    "scope-1",
		SecretName: "API_TOKEN",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected permission denied for revoked token, got %v", err)
	}
	if !bytes.Contains(serverBuf.Bytes(), []byte("secrets_denied")) {
		t.Fatalf("expected denial to be audited")
	}
	if !bytes.Contains(managerBuf.Bytes(), []byte(string(logging.EventSecretsTokenRev))) {
		t.Fatalf("expected revocation to be logged in manager audit log")
	}
}

func decodeAuditEvent(t *testing.T, data []byte) logging.AuditEvent {
	t.Helper()
	var event logging.AuditEvent
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatalf("decode audit event: %v", err)
	}
	return event
}
