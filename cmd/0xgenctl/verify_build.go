package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/reporter"
)

const (
	defaultReleaseRepo   = "RowanDark/0xgen"
	genericBuilderIDPath = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0"
	slsaVerifierBinary   = "slsa-verifier"
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

// verifierArgs is what runSlsaVerifier needs to shell out to the
// slsa-verifier CLI. Verification happens entirely in the external binary;
// this process never links against slsa-verifier's Go packages, which pull
// in cosign, sigstore, rekor, fulcio, docker, kubernetes, trillian, and the
// MongoDB driver.
type verifierArgs struct {
	artifactPath   string
	provenancePath string
	sourceURI      string
	tag            string
	builderID      string
}

// slsaVerifierRunner runs `slsa-verifier verify-artifact` and returns its
// combined output. A non-nil error means verification failed or the binary
// could not be run.
type slsaVerifierRunner func(ctx context.Context, args verifierArgs) (output string, err error)

var runSlsaVerifier slsaVerifierRunner = execSlsaVerifier

func execSlsaVerifier(ctx context.Context, args verifierArgs) (string, error) {
	bin, err := exec.LookPath(slsaVerifierBinary)
	if err != nil {
		return "", fmt.Errorf(
			"%s not found in PATH; install it from https://github.com/slsa-framework/slsa-verifier#installation and try again",
			slsaVerifierBinary,
		)
	}

	cmd := exec.CommandContext(ctx, bin, "verify-artifact",
		args.artifactPath,
		"--provenance-path", args.provenancePath,
		"--source-uri", args.sourceURI,
		"--source-tag", args.tag,
		"--builder-id", args.builderID,
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("slsa-verifier: %w", err)
	}
	return out.String(), nil
}

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

// dsseEnvelope is the minimal shape of an in-toto attestation's DSSE
// envelope, used only to pull display fields out of provenance that
// slsa-verifier has already cryptographically verified. It is never used to
// establish trust.
type dsseEnvelope struct {
	Payload string `json:"payload"`
}

func decodeStatement(provenance []byte) (inTotoStatement, error) {
	var stmt inTotoStatement
	line := provenance
	if idx := bytes.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	var envelope dsseEnvelope
	if err := json.Unmarshal(line, &envelope); err != nil {
		return stmt, fmt.Errorf("decode envelope: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return stmt, fmt.Errorf("decode payload: %w", err)
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return stmt, fmt.Errorf("decode statement: %w", err)
	}
	return stmt, nil
}

func runVerifyBuild(args []string) int {
	fs := flag.NewFlagSet("verify-build", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	artifactFlag := fs.String("artifact", "", "path to the artifact to verify (alternative to the positional argument)")
	attestationPath := fs.String("attestation", "", "path to provenance attestation (defaults to release asset)")
	provenancePath := fs.String("provenance", "", "alias for --attestation")
	repo := fs.String("repo", defaultReleaseRepo, "GitHub repository in owner/name form")
	tagFlag := fs.String("tag", "", "release tag to verify (defaults to the CLI version)")
	tokenFlag := fs.String("token", "", "GitHub token used for release queries (optional)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	artifactPath := strings.TrimSpace(*artifactFlag)
	if artifactPath == "" {
		remaining := fs.Args()
		if len(remaining) == 0 {
			fmt.Fprintln(os.Stderr, "artifact path is required")
			return 2
		}
		artifactPath = strings.TrimSpace(remaining[0])
	}
	artifactPath = filepath.Clean(artifactPath)
	if artifactPath == "" || artifactPath == "." {
		fmt.Fprintln(os.Stderr, "artifact path is required")
		return 2
	}

	attestation := strings.TrimSpace(*attestationPath)
	if attestation == "" {
		attestation = strings.TrimSpace(*provenancePath)
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

	var provenance []byte
	var localProvenancePath string
	provenanceSource := attestation
	if provenanceSource != "" {
		localProvenancePath = provenanceSource
		provenance, err = os.ReadFile(provenanceSource)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read attestation: %v\n", err)
			return 1
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		provenanceSource, provenance, err = activeFetcher.Fetch(ctx, repoOwner, repoName, tag, token)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "download provenance: %v\n", err)
			return 1
		}

		tmp, err := os.CreateTemp("", "0xgenctl-provenance-*.intoto.jsonl")
		if err != nil {
			fmt.Fprintf(os.Stderr, "stage provenance: %v\n", err)
			return 1
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(provenance); err != nil {
			tmp.Close()
			fmt.Fprintf(os.Stderr, "stage provenance: %v\n", err)
			return 1
		}
		if err := tmp.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "stage provenance: %v\n", err)
			return 1
		}
		localProvenancePath = tmp.Name()
	}

	sourceURI := fmt.Sprintf("git+https://github.com/%s/%s", repoOwner, repoName)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	output, err := runSlsaVerifier(ctx, verifierArgs{
		artifactPath:   artifactPath,
		provenancePath: localProvenancePath,
		sourceURI:      sourceURI,
		tag:            tag,
		builderID:      genericBuilderIDPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify build: %v\n", err)
		if strings.TrimSpace(output) != "" {
			fmt.Fprintln(os.Stderr, strings.TrimSpace(output))
		}
		return 1
	}

	fmt.Fprintf(os.Stdout, "Artifact: %s\n", artifactPath)
	fmt.Fprintf(os.Stdout, "Digest: %s\n", digestFull)
	fmt.Fprintf(os.Stdout, "Release tag: %s\n", tag)
	fmt.Fprintf(os.Stdout, "Source repository: %s\n", sourceURI)

	if statement, err := decodeStatement(provenance); err == nil {
		if statement.Predicate.Builder.ID != "" {
			fmt.Fprintf(os.Stdout, "Builder: %s\n", statement.Predicate.Builder.ID)
		}
		if commit, ok := statement.Predicate.Invocation.ConfigSource.Digest["sha1"]; ok && commit != "" {
			fmt.Fprintf(os.Stdout, "Source commit: %s\n", commit)
		}
		digest := strings.TrimPrefix(digestFull, "sha256:")
		if subjectName := matchSubject(statement.Subject, digest); subjectName != "" {
			fmt.Fprintf(os.Stdout, "Subject: %s\n", subjectName)
		}
		if statement.Predicate.Metadata.BuildInvocationID != "" {
			fmt.Fprintf(os.Stdout, "Build invocation: %s\n", statement.Predicate.Metadata.BuildInvocationID)
		}
	}

	fmt.Fprintf(os.Stdout, "Provenance: %s\n", provenanceSource)
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
