package updater

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"runtime"
	"strings"

	"github.com/RowanDark/0xgen/internal/env"
)

// DefaultBaseURL is the canonical CDN endpoint for update manifests.
const DefaultBaseURL = "https://updates.0xgen.dev"

// releasePublicKeyBase64 holds the Minisign/ed25519 public key that signs
// production manifests. Tests can override this value via the
// 0XGEN_UPDATER_PUBLIC_KEY environment variable.
const releasePublicKeyBase64 = "dWxmMeGnkd0vaZOZHgoEta/r/sMFAWacjsJfq4uhTl0="

// Manifest describes the set of builds published for a given channel.
type Manifest struct {
	Version  string       `json:"version"`
	NotesURL string       `json:"notes_url,omitempty"`
	Builds   []Build      `json:"builds"`
	Channel  string       `json:"channel"`
	Metadata ManifestMeta `json:"metadata,omitempty"`
}

// ManifestMeta records auxiliary information that is useful for telemetry and
// diagnostics but optional for clients.
type ManifestMeta struct {
	GeneratedAt string `json:"generated_at,omitempty"`
}

// Build describes how to update a specific OS/architecture pair.
type Build struct {
	OS    string   `json:"os"`
	Arch  string   `json:"arch"`
	Full  Artifact `json:"full"`
	Delta *Delta   `json:"delta,omitempty"`
}

// Artifact references a full binary installer.
type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// Delta references a patch that can be applied to a prior version of the
// binary.
type Delta struct {
	FromVersion string `json:"from_version"`
	URL         string `json:"url"`
	SHA256      string `json:"sha256"`
}

// BuildFor returns the build entry matching the provided platform.
func (m Manifest) BuildFor(goos, goarch string) (Build, bool) {
	for _, b := range m.Builds {
		if strings.EqualFold(b.OS, goos) && strings.EqualFold(b.Arch, goarch) {
			return b, true
		}
	}
	return Build{}, false
}

// DecodeManifest parses manifest JSON.
func DecodeManifest(data []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if strings.TrimSpace(m.Version) == "" {
		return Manifest{}, errors.New("manifest missing version")
	}
	if len(m.Builds) == 0 {
		return Manifest{}, errors.New("manifest missing builds")
	}
	return m, nil
}

// FetchManifest retrieves and verifies the manifest + signature for the given
// channel. It returns the parsed manifest and the raw manifest bytes.
func FetchManifest(ctx context.Context, client *http.Client, baseURL, channel string) (Manifest, []byte, error) {
	if client == nil {
		client = &http.Client{}
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	channel, err := NormalizeChannel(channel)
	if err != nil {
		return Manifest{}, nil, err
	}

	manifestURL, err := manifestURLFor(baseURL, channel)
	if err != nil {
		return Manifest{}, nil, err
	}
	manifestData, err := download(ctx, client, manifestURL, channel)
	if err != nil {
		return Manifest{}, nil, err
	}

	sigData, err := download(ctx, client, manifestURL+".sig", channel)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("download manifest signature: %w", err)
	}

	sig, err := decodeSignature(sigData)
	if err != nil {
		return Manifest{}, nil, err
	}

	pubKey, err := loadPublicKey()
	if err != nil {
		return Manifest{}, nil, err
	}
	if !ed25519.Verify(pubKey, manifestData, sig) {
		return Manifest{}, nil, errors.New("manifest signature verification failed")
	}

	manifest, err := DecodeManifest(manifestData)
	if err != nil {
		return Manifest{}, nil, err
	}
	return manifest, manifestData, nil
}

func manifestURLFor(baseURL, channel string) (string, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return "", errors.New("empty base URL")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}
	u.Path = path.Join(u.Path, channel, "manifest.json")
	return u.String(), nil
}

func download(ctx context.Context, client *http.Client, targetURL, channel string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("construct request: %w", err)
	}
	req.Header.Set("User-Agent", fmt.Sprintf("0xgenctl/%s (%s/%s)", runtime.Version(), runtime.GOOS, runtime.GOARCH))
	if channel != "" {
		req.Header.Set("X-0xgen-Update-Channel", channel)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", targetURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return nil, fmt.Errorf("download %s: unexpected status %d: %s", targetURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", targetURL, err)
	}
	return data, nil
}

func decodeSignature(raw []byte) ([]byte, error) {
	text := strings.TrimSpace(string(raw))
	sig, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature length %d", len(sig))
	}
	return sig, nil
}

func loadPublicKey() (ed25519.PublicKey, error) {
	if override, ok := env.Lookup("0XGEN_UPDATER_PUBLIC_KEY"); ok {
		trimmed := strings.TrimSpace(override)
		if trimmed != "" {
			key, err := base64.StdEncoding.DecodeString(trimmed)
			if err != nil {
				return nil, fmt.Errorf("decode 0XGEN_UPDATER_PUBLIC_KEY: %w", err)
			}
			if len(key) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("0XGEN_UPDATER_PUBLIC_KEY has invalid length %d", len(key))
			}
			return ed25519.PublicKey(key), nil
		}
	}
	key, err := base64.StdEncoding.DecodeString(releasePublicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode release public key: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("release public key has invalid length %d", len(key))
	}
	return ed25519.PublicKey(key), nil
}

// DecodeHex decodes a SHA256 checksum from a hex string into raw bytes.
func DecodeHex(sum string) ([]byte, error) {
	cleaned := strings.TrimSpace(sum)
	if len(cleaned) == 0 {
		return nil, errors.New("empty checksum")
	}
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("invalid checksum length %d", len(cleaned))
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decode checksum: %w", err)
	}
	return b, nil
}
