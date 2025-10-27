package team

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/logging"
)

func newTestLogger(t *testing.T) (*logging.AuditLogger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger, err := logging.NewAuditLogger("test", logging.WithWriter(&buf))
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	return logger, &buf
}

func TestWorkspaceLifecycleAndAuthorization(t *testing.T) {
	logger, buf := newTestLogger(t)
	store := NewStore(logger)

	ws, err := store.CreateWorkspace("Red Team", "owner")
	if err != nil {
		t.Fatalf("CreateWorkspace failed: %v", err)
	}
	if ws.ID == "" {
		t.Fatal("workspace id should not be empty")
	}
	if !store.Authorize(ws.ID, "owner", RoleAnalyst) {
		t.Fatal("owner should have analyst permissions")
	}
	if err := store.AddMember(ws.ID, "owner", "analyst", RoleAnalyst); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}
	if !store.Authorize(ws.ID, "analyst", RoleViewer) {
		t.Fatal("analyst should have viewer access")
	}
	if store.Authorize(ws.ID, "analyst", RoleAdmin) {
		t.Fatal("analyst should not have admin access")
	}
	if err := store.UpdateRole(ws.ID, "owner", "analyst", RoleAdmin); err != nil {
		t.Fatalf("UpdateRole failed: %v", err)
	}
	if !store.Authorize(ws.ID, "analyst", RoleAdmin) {
		t.Fatal("role update should promote analyst to admin")
	}
	if err := store.RemoveMember(ws.ID, "owner", "analyst"); err != nil {
		t.Fatalf("RemoveMember failed: %v", err)
	}
	if store.Authorize(ws.ID, "analyst", RoleViewer) {
		t.Fatal("removed member should not retain access")
	}

	entries := decodeEvents(t, buf.Bytes())
	if len(entries) == 0 {
		t.Fatal("expected audit entries to be recorded")
	}
}

func TestInviteFlowsAndCaseSharing(t *testing.T) {
	logger, _ := newTestLogger(t)
	store := NewStore(logger)

	ws, err := store.CreateWorkspace("Blue", "owner")
	if err != nil {
		t.Fatalf("CreateWorkspace failed: %v", err)
	}

	invite, err := store.GenerateInvite(ws.ID, "owner", RoleViewer, time.Minute)
	if err != nil {
		t.Fatalf("GenerateInvite failed: %v", err)
	}
	updated, role, err := store.ConsumeInvite(invite, "guest")
	if err != nil {
		t.Fatalf("ConsumeInvite failed: %v", err)
	}
	if updated.ID != ws.ID {
		t.Fatalf("expected workspace %s, got %s", ws.ID, updated.ID)
	}
	if role != RoleViewer {
		t.Fatalf("expected viewer role, got %s", role)
	}
	if !store.Authorize(ws.ID, "guest", RoleViewer) {
		t.Fatal("guest should now have viewer access")
	}

	caseToken, err := store.GenerateCaseInvite(ws.ID, "owner", "case-123", RoleViewer, time.Minute)
	if err != nil {
		t.Fatalf("GenerateCaseInvite failed: %v", err)
	}
	grant, err := store.ConsumeCaseInvite(caseToken, "external")
	if err != nil {
		t.Fatalf("ConsumeCaseInvite failed: %v", err)
	}
	if grant.WorkspaceID != ws.ID || grant.CaseID != "case-123" {
		t.Fatalf("unexpected case grant: %+v", grant)
	}
	if !store.HasCaseAccess(ws.ID, "external", "case-123", RoleViewer) {
		t.Fatal("external user should have case access")
	}
	if store.HasCaseAccess(ws.ID, "external", "case-unknown", RoleViewer) {
		t.Fatal("access should be scoped to invited case")
	}
}

func TestConsumeInviteHonoursExpiry(t *testing.T) {
	logger, _ := newTestLogger(t)
	store := NewStore(logger)
	ws, err := store.CreateWorkspace("Green", "owner")
	if err != nil {
		t.Fatalf("CreateWorkspace failed: %v", err)
	}
	token, err := store.GenerateInvite(ws.ID, "owner", RoleViewer, time.Millisecond)
	if err != nil {
		t.Fatalf("GenerateInvite failed: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, _, err := store.ConsumeInvite(token, "late"); err == nil {
		t.Fatal("expected invite to expire")
	}
}

func decodeEvents(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	var out []map[string]any
	for {
		var entry map[string]any
		if err := dec.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("failed to decode audit log entry: %v", err)
		}
		out = append(out, entry)
	}
	return out
}
