package secrets

import (
	"errors"
	"testing"
	"time"
)

func TestManagerIssueAndResolve(t *testing.T) {
	current := time.Unix(0, 0).UTC()
	clock := func() time.Time { return current }
	mgr := NewManager(map[string]map[string]string{
		"seer": {"api_token": "super-secret"},
	}, WithClock(clock), WithTTL(2*time.Minute))

	token, expires, err := mgr.Issue("seer", "run-1", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if token == "" {
		t.Fatalf("expected token to be issued")
	}
	if want := current.Add(2 * time.Minute); !expires.Equal(want) {
		t.Fatalf("expected expiry %v, got %v", want, expires)
	}

	value, err := mgr.Resolve(token, "seer", "run-1", "API_TOKEN")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if value != "super-secret" {
		t.Fatalf("unexpected secret value %q", value)
	}

	nextToken, _, err := mgr.Issue("seer", "run-1", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("Issue second token: %v", err)
	}
	if nextToken == token {
		t.Fatalf("expected new token per issuance")
	}

	current = current.Add(5 * time.Minute)
	if _, err := mgr.Resolve(token, "seer", "run-1", "API_TOKEN"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired after ttl, got %v", err)
	}
}

func TestManagerDeniesUnknownSecret(t *testing.T) {
	mgr := NewManager(map[string]map[string]string{
		"seer": {"api_token": "super-secret"},
	})
	token, _, err := mgr.Issue("seer", "scope-a", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if _, err := mgr.Resolve(token, "seer", "scope-a", "DB_PASSWORD"); !errors.Is(err, ErrSecretNotGranted) {
		t.Fatalf("expected ErrSecretNotGranted, got %v", err)
	}
	if _, _, err := mgr.Issue("seer", "scope-a", []string{"DB_PASSWORD"}); !errors.Is(err, ErrSecretNotProvisioned) {
		t.Fatalf("expected ErrSecretNotProvisioned, got %v", err)
	}
}

func TestManagerRejectsMismatchedScope(t *testing.T) {
	mgr := NewManager(map[string]map[string]string{
		"seer": {"api_token": "super-secret"},
	})
	token, _, err := mgr.Issue("seer", "run-123", []string{"API_TOKEN"})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if _, err := mgr.Resolve(token, "seer", "run-456", "API_TOKEN"); !errors.Is(err, ErrTokenScopeMismatch) {
		t.Fatalf("expected ErrTokenScopeMismatch, got %v", err)
	}
}
