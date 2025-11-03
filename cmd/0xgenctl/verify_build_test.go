package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RowanDark/0xgen/internal/reporter"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
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
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	stub := &stubFetcher{data: []byte("attestation")}
	originalFetcher := activeFetcher
	activeFetcher = stub
	t.Cleanup(func() { activeFetcher = originalFetcher })

	builder, err := utils.TrustedBuilderIDNew(genericBuilderIDPath, false)
	if err != nil {
		t.Fatalf("builder id: %v", err)
	}

	originalVerifier := verifyProvenance
	verifyProvenance = func(ctx context.Context, prov []byte, artifactHash string, provOpts *options.ProvenanceOpts, builderOpts *options.BuilderOpts) ([]byte, *utils.TrustedBuilderID, error) {
		if !bytes.Equal(prov, stub.data) {
			t.Fatalf("unexpected provenance payload")
		}
		if artifactHash != digest {
			t.Fatalf("expected digest %s, got %s", digest, artifactHash)
		}
		if provOpts.ExpectedDigest != digest {
			t.Fatalf("expected digest in opts")
		}
		return payload, builder, nil
	}
	t.Cleanup(func() { verifyProvenance = originalVerifier })

	if code := runVerifyBuild([]string{"--tag", "v1.2.3", artifact}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !stub.called {
		t.Fatalf("expected fetcher to be called")
	}
}
