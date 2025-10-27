package integrity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/RowanDark/0xgen/internal/plugins"
)

func TestVerifySignaturePublicKey(t *testing.T) {
	artifactSrc := filepath.Join("testdata", "artifact.txt")
	data, err := os.ReadFile(artifactSrc)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}

	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact.txt")
	if err := os.WriteFile(artifact, data, 0o644); err != nil {
		t.Fatalf("write artifact copy: %v", err)
	}

	sigPath, keyPath := writeSignatureFixtures(t, dir, artifact)

	sig := &plugins.Signature{Signature: filepath.Base(sigPath), PublicKey: filepath.Base(keyPath)}
	if err := VerifySignature(artifact, dir, dir, sig); err != nil {
		t.Fatalf("expected signature verification to succeed: %v", err)
	}
}

func TestVerifySignatureTamper(t *testing.T) {
	artifactSrc := filepath.Join("testdata", "artifact.txt")
	data, err := os.ReadFile(artifactSrc)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}

	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact.txt")
	if err := os.WriteFile(artifact, data, 0o644); err != nil {
		t.Fatalf("write artifact copy: %v", err)
	}

	sigPath, keyPath := writeSignatureFixtures(t, dir, artifact)

	tamperedDir := t.TempDir()
	tampered := filepath.Join(tamperedDir, "artifact.txt")
	if err := os.WriteFile(tampered, append(data, []byte("tamper")...), 0o644); err != nil {
		t.Fatalf("write tampered artifact: %v", err)
	}

	sig := &plugins.Signature{Signature: filepath.Base(sigPath), PublicKey: filepath.Base(keyPath)}
	if err := VerifySignature(tampered, dir, dir, sig); err == nil {
		t.Fatalf("expected signature verification to fail for tampered artifact")
	}
}

func writeSignatureFixtures(t *testing.T, dir, artifact string) (string, string) {
	t.Helper()

	contents, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	digest := sha256Sum(contents)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		t.Fatalf("sign artifact: %v", err)
	}

	sigPath := filepath.Join(dir, "artifact.txt.sig")
	encodedSig := base64.StdEncoding.EncodeToString(signature)
	if err := os.WriteFile(sigPath, []byte(encodedSig), 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	keyPath := filepath.Join(dir, "artifact.pub")
	if err := os.WriteFile(keyPath, pemBytes, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return sigPath, keyPath
}

func sha256Sum(data []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func TestVerifySignatureRejectsPathTraversal(t *testing.T) {
	pluginDir := t.TempDir()
	artifact := filepath.Join(pluginDir, "artifact.txt")
	if err := os.WriteFile(artifact, []byte("data"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	sig := &plugins.Signature{
		Signature: "../escape.sig",
		PublicKey: "../escape.pub",
	}
	if err := VerifySignature(artifact, pluginDir, filepath.Dir(pluginDir), sig); err == nil {
		t.Fatalf("expected verification to fail for escaping signature paths")
	}
}
