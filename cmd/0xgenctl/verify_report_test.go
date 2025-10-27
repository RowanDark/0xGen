package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/RowanDark/0xgen/internal/reporter"
)

func TestRunVerifyReportSuccess(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	artifact := filepath.Join(dir, "report.json")
	if err := os.WriteFile(artifact, []byte(`{"schema_version":"1.0"}`), 0o644); err != nil {
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
	privPath := filepath.Join(dir, "cosign.key")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if _, err := reporter.SignArtifact(artifact, privPath); err != nil {
		t.Fatalf("sign artifact: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPath := filepath.Join(dir, "cosign.pub")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}), 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	if code := runVerifyReport([]string{"--key", pubPath, artifact}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunVerifyReportMissingKey(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	if code := runVerifyReport([]string{"report.json"}); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunVerifyReportDetectsTampering(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	artifact := filepath.Join(dir, "report.json")
	if err := os.WriteFile(artifact, []byte(`{"schema_version":"1.0"}`), 0o644); err != nil {
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
	privPath := filepath.Join(dir, "cosign.key")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if _, err := reporter.SignArtifact(artifact, privPath); err != nil {
		t.Fatalf("sign artifact: %v", err)
	}

	if err := os.WriteFile(artifact, []byte(`{"schema_version":"2.0"}`), 0o644); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPath := filepath.Join(dir, "cosign.pub")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}), 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	if code := runVerifyReport([]string{"--key", pubPath, artifact}); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}
