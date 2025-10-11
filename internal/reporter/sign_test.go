package reporter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignArtifactProducesValidSignature(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(artifactPath, []byte(`{"schema_version":"1.0"}`), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	keyPath := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	t.Setenv("COSIGN_PASSWORD", "")

	sigPath, err := SignArtifact(artifactPath, keyPath)
	if err != nil {
		t.Fatalf("sign artifact: %v", err)
	}
	if sigPath != artifactPath+".sig" {
		t.Fatalf("unexpected signature path %s", sigPath)
	}

	signatureB64, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureB64)))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	digest, err := computeFileDigest(artifactPath)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}

	if !ecdsa.VerifyASN1(&key.PublicKey, digest, signature) {
		t.Fatalf("signature verification failed")
	}
}
