package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RowanDark/0xgen/internal/reporter"
)

type failingFetcher struct{}

func (f *failingFetcher) Fetch(_ context.Context, _, _, _, _ string) (string, []byte, error) {
	return "", nil, errors.New("fetch error")
}

type stubFetcher struct {
	called bool
	data   []byte
}

func (s *stubFetcher) Fetch(_ context.Context, _, _, _, _ string) (string, []byte, error) {
	s.called = true
	return "remote.intoto", s.data, nil
}

func encodeProvenance(t *testing.T, statement map[string]any) []byte {
	t.Helper()
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	envelope := map[string]string{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(payload),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return data
}

func TestRunVerifyBuildRequiresArtifact(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	if code := runVerifyBuild(nil); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunVerifyBuildInvalidRepo(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(artifact, []byte("data"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	if code := runVerifyBuild([]string{"--repo", "not-a-repo", "--tag", "v1.2.3", artifact}); code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunVerifyBuildAttestationError(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(artifact, []byte("data"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	if code := runVerifyBuild([]string{"--attestation", filepath.Join(dir, "missing.intoto"), "--tag", "v1.2.3", artifact}); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRunVerifyBuildFetchError(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(artifact, []byte("data"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	originalFetcher := activeFetcher
	activeFetcher = &failingFetcher{}
	t.Cleanup(func() { activeFetcher = originalFetcher })

	if code := runVerifyBuild([]string{"--tag", "v1.2.3", artifact}); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRunVerifyBuildVerifierNotFound(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(artifact, []byte("data"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	attestation := filepath.Join(dir, "provenance.intoto.jsonl")
	if err := os.WriteFile(attestation, encodeProvenance(t, map[string]any{}), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}

	originalRunner := runSlsaVerifier
	runSlsaVerifier = func(_ context.Context, _ verifierArgs) (string, error) {
		return "", errors.New("slsa-verifier not found in PATH")
	}
	t.Cleanup(func() { runSlsaVerifier = originalRunner })

	code := runVerifyBuild([]string{"--attestation", attestation, "--tag", "v1.2.3", artifact})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRunVerifyBuildSuccessWithFetcher(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact.bin")
	contents := []byte("hello world")
	if err := os.WriteFile(artifact, contents, 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	digest, err := reporter.ComputeFileDigestHex(artifact)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	digest = strings.TrimPrefix(digest, "sha256:")

	statement := map[string]any{
		"subject": []map[string]any{{
			"name":   "artifact.bin",
			"digest": map[string]string{"sha256": digest},
		}},
		"predicate": map[string]any{
			"builder": map[string]string{"id": genericBuilderIDPath},
			"invocation": map[string]any{
				"configSource": map[string]any{
					"uri":    "git+https://github.com/RowanDark/0xgen",
					"digest": map[string]string{"sha1": "deadbeef"},
				},
			},
			"metadata": map[string]string{"buildInvocationID": "123"},
		},
	}
	provenance := encodeProvenance(t, statement)

	stub := &stubFetcher{data: provenance}
	originalFetcher := activeFetcher
	activeFetcher = stub
	t.Cleanup(func() { activeFetcher = originalFetcher })

	var gotArgs verifierArgs
	originalRunner := runSlsaVerifier
	runSlsaVerifier = func(_ context.Context, args verifierArgs) (string, error) {
		gotArgs = args
		data, err := os.ReadFile(args.provenancePath)
		if err != nil {
			t.Fatalf("read staged provenance: %v", err)
		}
		if string(data) != string(provenance) {
			t.Fatalf("unexpected staged provenance contents")
		}
		return "PASSED\n", nil
	}
	t.Cleanup(func() { runSlsaVerifier = originalRunner })

	if code := runVerifyBuild([]string{"--tag", "v1.2.3", artifact}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !stub.called {
		t.Fatalf("expected fetcher to be called")
	}
	if gotArgs.artifactPath != filepath.Clean(artifact) {
		t.Fatalf("unexpected artifact path: %s", gotArgs.artifactPath)
	}
	if gotArgs.sourceURI != "git+https://github.com/RowanDark/0xgen" {
		t.Fatalf("unexpected source URI: %s", gotArgs.sourceURI)
	}
	if gotArgs.tag != "v1.2.3" {
		t.Fatalf("unexpected tag: %s", gotArgs.tag)
	}
	if gotArgs.builderID != genericBuilderIDPath {
		t.Fatalf("unexpected builder ID: %s", gotArgs.builderID)
	}
}

func TestRunVerifyBuildArtifactFlag(t *testing.T) {
	restore := silenceOutput(t)
	defer restore()

	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(artifact, []byte("data"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	attestation := filepath.Join(dir, "provenance.intoto.jsonl")
	if err := os.WriteFile(attestation, encodeProvenance(t, map[string]any{}), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}

	var gotArgs verifierArgs
	originalRunner := runSlsaVerifier
	runSlsaVerifier = func(_ context.Context, args verifierArgs) (string, error) {
		gotArgs = args
		return "PASSED\n", nil
	}
	t.Cleanup(func() { runSlsaVerifier = originalRunner })

	code := runVerifyBuild([]string{"--artifact", artifact, "--attestation", attestation, "--tag", "v1.2.3"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if gotArgs.artifactPath != filepath.Clean(artifact) {
		t.Fatalf("unexpected artifact path: %s", gotArgs.artifactPath)
	}
}
