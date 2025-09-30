package integrity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RowanDark/Glyph/internal/plugins"
)

func TestVerifySignaturePublicKey(t *testing.T) {
	dir := filepath.Join("testdata")
	artifact := filepath.Join(dir, "artifact.txt")
	sig := &plugins.Signature{
		Signature: "artifact.txt.sig",
		PublicKey: "glyph-plugin.pub",
	}
	if err := VerifySignature(artifact, dir, dir, sig); err != nil {
		t.Fatalf("expected signature verification to succeed: %v", err)
	}
}

func TestVerifySignatureTamper(t *testing.T) {
	dir := filepath.Join("testdata")
	artifact := filepath.Join(dir, "artifact.txt")
	contents, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	tmp := t.TempDir()
	tampered := filepath.Join(tmp, "artifact.txt")
	if err := os.WriteFile(tampered, append(contents, []byte("tamper")...), 0o644); err != nil {
		t.Fatalf("write tampered artifact: %v", err)
	}
	sig := &plugins.Signature{
		Signature: "artifact.txt.sig",
		PublicKey: "glyph-plugin.pub",
	}
	if err := VerifySignature(tampered, dir, dir, sig); err == nil {
		t.Fatalf("expected signature verification to fail for tampered artifact")
	}
}
