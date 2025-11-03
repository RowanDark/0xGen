package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/reporter"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers"
)

const (
	defaultReleaseRepo   = "RowanDark/0xgen"
	genericBuilderIDPath = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0"
)

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type releaseResponse struct {
	Assets []releaseAsset `json:"assets"`
}

type provenanceFetcher interface {
	Fetch(ctx context.Context, owner, repo, tag, token string) (string, []byte, error)
}

type githubFetcher struct {
	client *http.Client
}

func newGithubFetcher() *githubFetcher {
	return &githubFetcher{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (g *githubFetcher) Fetch(ctx context.Context, owner, repo, tag, token string) (string, []byte, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "0xgenctl-verify-build")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	res, err := g.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("query release: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return "", nil, fmt.Errorf("release lookup failed: %s: %s", res.Status, strings.TrimSpace(string(body)))
	}

	var payload releaseResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return "", nil, fmt.Errorf("decode release response: %w", err)
	}

	expected := fmt.Sprintf("0xgen-%s-provenance.intoto.jsonl", tag)
	var assetURL, assetName string
	for _, asset := range payload.Assets {
		if asset.Name == expected {
			assetURL = asset.BrowserDownloadURL
			assetName = asset.Name
			break
		}
	}
	if assetURL == "" {
		return "", nil, fmt.Errorf("provenance asset %q not found in release", expected)
	}

	downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return "", nil, fmt.Errorf("build download request: %w", err)
	}
	downloadReq.Header.Set("Accept", "application/octet-stream")
	downloadReq.Header.Set("User-Agent", "0xgenctl-verify-build")
	if token != "" {
		downloadReq.Header.Set("Authorization", "Bearer "+token)
	}

	downloadRes, err := g.client.Do(downloadReq)
	if err != nil {
		return "", nil, fmt.Errorf("download provenance: %w", err)
	}
	defer downloadRes.Body.Close()

	if downloadRes.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(downloadRes.Body, 4096))
		return "", nil, fmt.Errorf("download provenance failed: %s: %s", downloadRes.Status, strings.TrimSpace(string(body)))
	}

	data, err := io.ReadAll(downloadRes.Body)
	if err != nil {
		return "", nil, fmt.Errorf("read provenance: %w", err)
	}
	return assetName, data, nil
}

var activeFetcher provenanceFetcher = newGithubFetcher()
var verifyProvenance = verifiers.VerifyArtifact

type inTotoStatement struct {
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		Invocation struct {
			ConfigSource struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"configSource"`
		} `json:"invocation"`
		Metadata struct {
			BuildInvocationID string `json:"buildInvocationID"`
			BuildStartedOn    string `json:"buildStartedOn"`
			BuildFinishedOn   string `json:"buildFinishedOn"`
		} `json:"metadata"`
	} `json:"predicate"`
}

func runVerifyBuild(args []string) int {
	fs := flag.NewFlagSet("verify-build", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	attestationPath := fs.String("attestation", "", "path to provenance attestation (defaults to release asset)")
	repo := fs.String("repo", defaultReleaseRepo, "GitHub repository in owner/name form")
	tagFlag := fs.String("tag", "", "release tag to verify (defaults to the CLI version)")
	tokenFlag := fs.String("token", "", "GitHub token used for release queries (optional)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "artifact path is required")
		return 2
	}

	artifactPath := filepath.Clean(strings.TrimSpace(remaining[0]))
	if artifactPath == "" {
		fmt.Fprintln(os.Stderr, "artifact path is required")
		return 2
	}

	repoOwner, repoName, err := splitRepo(strings.TrimSpace(*repo))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --repo: %v\n", err)
		return 2
	}

	tag := normalizeTag(strings.TrimSpace(*tagFlag))
	if tag == "" {
		tag = normalizeTag(strings.TrimSpace(version))
	}
	if tag == "" || strings.EqualFold(tag, "vdev") || strings.EqualFold(tag, "dev") {
		fmt.Fprintln(os.Stderr, "unable to determine release tag; specify --tag")
		return 2
	}

	token := strings.TrimSpace(*tokenFlag)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}

	digestFull, err := reporter.ComputeFileDigestHex(artifactPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash artifact: %v\n", err)
		return 1
	}
	digest := strings.TrimPrefix(digestFull, "sha256:")
	if digest == "" || len(digest) != len(digestFull)-len("sha256:") {
		fmt.Fprintln(os.Stderr, "unexpected digest format")
		return 1
	}

	var provenance []byte
	provenanceSource := strings.TrimSpace(*attestationPath)
	if provenanceSource != "" {
		provenance, err = os.ReadFile(provenanceSource)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read attestation: %v\n", err)
			return 1
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		provenanceSource, provenance, err = activeFetcher.Fetch(ctx, repoOwner, repoName, tag, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "download provenance: %v\n", err)
			return 1
		}
	}

	sourceURI := fmt.Sprintf("git+https://github.com/%s/%s", repoOwner, repoName)
	tagRef := fmt.Sprintf("refs/tags/%s", tag)
	builderID := genericBuilderIDPath

	provOpts := &options.ProvenanceOpts{
		ExpectedDigest:       digest,
		ExpectedSourceURI:    sourceURI,
		ExpectedTag:          &tagRef,
		ExpectedVersionedTag: &tag,
	}
	builderOpts := &options.BuilderOpts{ExpectedID: &builderID}

	verified, builder, err := verifyProvenance(context.Background(), provenance, digest, provOpts, builderOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify build: %v\n", err)
		return 1
	}

	var statement inTotoStatement
	if err := json.Unmarshal(verified, &statement); err != nil {
		fmt.Fprintf(os.Stderr, "decode provenance payload: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "Artifact: %s\n", artifactPath)
	fmt.Fprintf(os.Stdout, "Digest: %s\n", digestFull)
	fmt.Fprintf(os.Stdout, "Release tag: %s\n", tag)
	fmt.Fprintf(os.Stdout, "Source repository: %s\n", sourceURI)
	if builder != nil {
		fmt.Fprintf(os.Stdout, "Builder: %s\n", builder.String())
	}
	if statement.Predicate.Invocation.ConfigSource.Digest != nil {
		if commit, ok := statement.Predicate.Invocation.ConfigSource.Digest["sha1"]; ok && commit != "" {
			fmt.Fprintf(os.Stdout, "Source commit: %s\n", commit)
		}
	}
	fmt.Fprintf(os.Stdout, "Provenance: %s\n", provenanceSource)

	subjectName := matchSubject(statement.Subject, digest)
	if subjectName != "" {
		fmt.Fprintf(os.Stdout, "Subject: %s\n", subjectName)
	}

	if statement.Predicate.Metadata.BuildInvocationID != "" {
		fmt.Fprintf(os.Stdout, "Build invocation: %s\n", statement.Predicate.Metadata.BuildInvocationID)
	}
	fmt.Fprintln(os.Stdout, "Build provenance verified.")
	return 0
}

func matchSubject(subjects []struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}, digest string) string {
	for _, subject := range subjects {
		if subject.Digest == nil {
			continue
		}
		if value, ok := subject.Digest["sha256"]; ok && strings.EqualFold(value, digest) {
			return subject.Name
		}
	}
	return ""
}

func normalizeTag(tag string) string {
	trimmed := strings.TrimSpace(tag)
	trimmed = strings.TrimPrefix(trimmed, "refs/tags/")
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "v") {
		return "v" + trimmed
	}
	return trimmed
}

func splitRepo(value string) (string, string, error) {
	cleaned := strings.TrimSpace(value)
	parts := strings.Split(cleaned, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", errors.New("expected owner/name")
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}
