package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/reporter"
)

func TestRunReportSuccess(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	input := filepath.Join(dir, "findings.jsonl")
	output := filepath.Join(dir, "report.md")

	writer := reporter.NewJSONL(input)
	sample := findings.Finding{
		Version:    findings.SchemaVersion,
		ID:         findings.NewID(),
		Plugin:     "p",
		Type:       "t",
		Message:    "m",
		Target:     "https://example.com",
		Evidence:   "issue",
		Severity:   findings.SeverityLow,
		DetectedAt: findings.NewTimestamp(time.Unix(1710000000, 0).UTC()),
	}
	if err := writer.Write(sample); err != nil {
		t.Fatalf("write finding: %v", err)
	}

	now := time.Date(2024, 2, 1, 12, 0, 0, 0, time.UTC)
	if code := runReportAt([]string{"--input", input, "--out", output}, now); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "## Totals by Severity") {
		t.Fatalf("report missing severity section: %s", content)
	}
	if !strings.Contains(content, "## Last 20 Findings") {
		t.Fatalf("report missing recent findings section: %s", content)
	}
	if !strings.Contains(content, "issue") {
		t.Fatalf("report missing evidence excerpt: %s", content)
	}
}

func TestRunReportMissingArgs(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	if code := runReport([]string{"--input", "", "--out", ""}); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunReportMatchesGolden(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	output := filepath.Join(dir, "report.md")
	input := filepath.Join("testdata", "findings.jsonl")

	now := time.Date(2024, 2, 1, 12, 0, 0, 0, time.UTC)
	if code := runReportAt([]string{"--input", input, "--out", output}, now); code != 0 {
		t.Fatalf("runReport exited with %d", code)
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read generated report: %v", err)
	}

	goldenPath := filepath.Join("testdata", "report_no_filter.golden")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	if string(got) != string(want) {
		t.Fatalf("report mismatch\nwant:\n%s\n\ngot:\n%s", string(want), string(got))
	}
}

func TestRunReportSince24hMatchesGolden(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	output := filepath.Join(dir, "report.md")
	input := filepath.Join("testdata", "findings.jsonl")

	now := time.Date(2024, 2, 1, 12, 0, 0, 0, time.UTC)
	if code := runReportAt([]string{"--input", input, "--out", output, "--since", "24h"}, now); code != 0 {
		t.Fatalf("runReport exited with %d", code)
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read generated report: %v", err)
	}

	goldenPath := filepath.Join("testdata", "report_since_24h.golden")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	if string(got) != string(want) {
		t.Fatalf("report mismatch\nwant:\n%s\n\ngot:\n%s", string(want), string(got))
	}
}

func TestRunReportInvalidSince(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	now := time.Date(2024, 2, 1, 12, 0, 0, 0, time.UTC)
	if code := runReportAt([]string{"--input", "in", "--out", "out", "--since", "nonsense"}, now); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunReportJSONSigning(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	input := filepath.Join(dir, "findings.jsonl")
	output := filepath.Join(dir, "report.json")
	sbomPath := filepath.Join(dir, "sbom.spdx")

	if err := os.WriteFile(sbomPath, []byte("SPDX"), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	writer := reporter.NewJSONL(input)
	sample := findings.Finding{
		Version:    findings.SchemaVersion,
		ID:         findings.NewID(),
		Plugin:     "collector",
		Type:       "exposure",
		Message:    "demo",
		Target:     "service",
		Severity:   findings.SeverityMedium,
		DetectedAt: findings.NewTimestamp(time.Unix(1710001000, 0).UTC()),
	}
	if err := writer.Write(sample); err != nil {
		t.Fatalf("write finding: %v", err)
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
	keyPath := filepath.Join(dir, "sign.key")
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	now := time.Date(2024, 3, 5, 9, 0, 0, 0, time.UTC)
	args := []string{"--input", input, "--out", output, "--format", "json", "--sign", keyPath, "--sbom", sbomPath}
	if code := runReportAt(args, now); code != 0 {
		t.Fatalf("runReport exited with %d", code)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read json: %v", err)
	}

	var payload struct {
		SchemaVersion string `json:"schema_version"`
		SBOM          struct {
			Digest struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"digest"`
		} `json:"sbom"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if payload.SchemaVersion != reporter.BundleSchemaVersion {
		t.Fatalf("unexpected schema version %q", payload.SchemaVersion)
	}

	expectedDigest, err := reporter.ComputeFileDigestHex(sbomPath)
	if err != nil {
		t.Fatalf("digest sbom: %v", err)
	}
	actualDigest := payload.SBOM.Digest.Algorithm + ":" + payload.SBOM.Digest.Value
	if actualDigest != expectedDigest {
		t.Fatalf("unexpected sbom digest %s want %s", actualDigest, expectedDigest)
	}

	signatureData, err := os.ReadFile(output + ".sig")
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureData)))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sigBytes) {
		t.Fatalf("signature verification failed")
	}
}
