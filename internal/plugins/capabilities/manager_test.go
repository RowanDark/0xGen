package capabilities

import (
	"strings"
	"testing"
	"time"
)

func TestManagerIssueAndValidate(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	manager := NewManager(WithClock(clock), WithTTL(time.Minute))

	token, expires, err := manager.Issue("plugin", []string{"cap_one", "CAP_TWO"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if token == "" {
		t.Fatal("expected token to be populated")
	}
	if !expires.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected expiry: %s", expires)
	}

	caps, err := manager.Validate(token, "plugin", []string{"cap_two"})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(caps) != 1 || caps[0] != "CAP_TWO" {
		t.Fatalf("unexpected capabilities: %v", caps)
	}

	if manager.Remaining() != 0 {
		t.Fatalf("expected grant to be consumed, remaining=%d", manager.Remaining())
	}
}

func TestManagerValidateRejectsEscalation(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	manager := NewManager(WithClock(clock), WithTTL(time.Minute))

	token, _, err := manager.Issue("plugin", []string{"CAP_ONE"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	_, err = manager.Validate(token, "plugin", []string{"CAP_TWO"})
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	if !strings.Contains(err.Error(), "CAP_TWO") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerValidateRejectsExpired(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	manager := NewManager(WithClock(clock), WithTTL(time.Millisecond))

	token, _, err := manager.Issue("plugin", []string{"CAP_ONE"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Advance clock beyond expiry.
	late := func() time.Time { return now.Add(time.Second) }
	manager.clock = late

	if _, err := manager.Validate(token, "plugin", []string{"CAP_ONE"}); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}
