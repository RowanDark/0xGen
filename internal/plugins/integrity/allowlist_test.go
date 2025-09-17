package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllowlistVerify(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(artifact, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	hash, err := hashFile(artifact)
	if err != nil {
		t.Fatalf("hash artifact: %v", err)
	}

	allowlistPath := filepath.Join(dir, "ALLOWLIST")
	content := hash + " sample.txt\n"
	if err := os.WriteFile(allowlistPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}

	allowlist, err := LoadAllowlist(allowlistPath)
	if err != nil {
		t.Fatalf("load allowlist: %v", err)
	}

	if err := allowlist.Verify(artifact); err != nil {
		t.Fatalf("verify: %v", err)
	}

	if err := os.WriteFile(artifact, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}
	if err := allowlist.Verify(artifact); err == nil {
		t.Fatal("expected verification failure after tampering")
	}
}
