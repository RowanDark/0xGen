package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnforcerFromFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	policy := `
version: 1
allow:
  - type: domain
    value: example.com
`
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	enforcer, err := LoadEnforcerFromFile(path)
	if err != nil {
		t.Fatalf("load enforcer: %v", err)
	}

	decision := enforcer.Evaluate("https://example.com")
	if !decision.Allowed {
		t.Fatalf("expected example.com to be allowed, got %+v", decision)
	}
	decision = enforcer.Evaluate("https://blocked.invalid")
	if decision.Allowed {
		t.Fatalf("expected blocked.invalid to be denied")
	}
}

func TestLoadPolicyFromFileMissing(t *testing.T) {
	t.Parallel()

	if _, err := LoadPolicyFromFile(" "); err == nil {
		t.Fatal("expected error for empty path")
	}
	if _, err := LoadPolicyFromFile("/does/not/exist.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
