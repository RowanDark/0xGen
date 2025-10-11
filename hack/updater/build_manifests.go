package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RowanDark/Glyph/internal/updater"
)

type artifactInput struct {
	URL    string `json:"url"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type deltaInput struct {
	FromVersion string `json:"from_version"`
	URL         string `json:"url"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
}

type buildInput struct {
	OS    string        `json:"os"`
	Arch  string        `json:"arch"`
	Full  artifactInput `json:"full"`
	Delta *deltaInput   `json:"delta"`
}

type channelInput struct {
	Channel  string       `json:"channel"`
	Version  string       `json:"version"`
	NotesURL string       `json:"notes_url"`
	Builds   []buildInput `json:"builds"`
}

func main() {
	configDir := flag.String("config", "packaging/updater", "channel configuration directory")
	outDir := flag.String("out", "out/updater", "output directory for manifests")
	flag.Parse()

	key, err := loadSigningKey()
	if err != nil {
		fatal(err)
	}

	entries, err := os.ReadDir(*configDir)
	if err != nil {
		fatal(fmt.Errorf("read config dir: %w", err))
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(fmt.Errorf("create output dir: %w", err))
	}

	var configs []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".example.json") {
			continue
		}
		configs = append(configs, filepath.Join(*configDir, entry.Name()))
	}
	sort.Strings(configs)

	if len(configs) == 0 {
		fatal(errors.New("no channel configuration files found"))
	}

	for _, file := range configs {
		if err := processChannel(file, *outDir, key); err != nil {
			fatal(fmt.Errorf("%s: %w", file, err))
		}
	}
}

func processChannel(path string, outDir string, key ed25519.PrivateKey) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var input channelInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	channel, err := updater.NormalizeChannel(input.Channel)
	if err != nil {
		return fmt.Errorf("normalise channel: %w", err)
	}
	if strings.TrimSpace(input.Version) == "" {
		return errors.New("version is required")
	}
	if len(input.Builds) == 0 {
		return errors.New("at least one build must be defined")
	}

	manifest := updater.Manifest{
		Version:  strings.TrimSpace(input.Version),
		Channel:  channel,
		NotesURL: strings.TrimSpace(input.NotesURL),
		Metadata: updater.ManifestMeta{GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
	}

	baseDir := filepath.Dir(path)
	for i, build := range input.Builds {
		if strings.TrimSpace(build.OS) == "" || strings.TrimSpace(build.Arch) == "" {
			return fmt.Errorf("build %d missing os/arch", i)
		}
		full, err := resolveArtifact(build.Full, baseDir)
		if err != nil {
			return fmt.Errorf("build %d full artifact: %w", i, err)
		}
		var delta *updater.Delta
		if build.Delta != nil {
			d, err := resolveDelta(*build.Delta, baseDir)
			if err != nil {
				return fmt.Errorf("build %d delta: %w", i, err)
			}
			delta = &d
		}
		manifest.Builds = append(manifest.Builds, updater.Build{
			OS:    strings.TrimSpace(build.OS),
			Arch:  strings.TrimSpace(build.Arch),
			Full:  full,
			Delta: delta,
		})
	}

	manifestPath := filepath.Join(outDir, channel, "manifest.json")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		return fmt.Errorf("create manifest dir: %w", err)
	}
	if err := writeManifest(manifestPath, manifest); err != nil {
		return err
	}
	return writeSignature(manifestPath, key)
}

func resolveArtifact(in artifactInput, baseDir string) (updater.Artifact, error) {
	url := strings.TrimSpace(in.URL)
	if url == "" {
		return updater.Artifact{}, errors.New("artifact url is required")
	}
	sha := strings.TrimSpace(in.SHA256)
	if sha == "" {
		path := resolvePath(in.Path, baseDir)
		if path == "" {
			return updater.Artifact{}, errors.New("artifact sha256 or path must be provided")
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return updater.Artifact{}, err
		}
		sha = sum
	}
	return updater.Artifact{URL: url, SHA256: sha}, nil
}

func resolveDelta(in deltaInput, baseDir string) (updater.Delta, error) {
	if strings.TrimSpace(in.FromVersion) == "" {
		return updater.Delta{}, errors.New("delta from_version is required")
	}
	art, err := resolveArtifact(artifactInput{URL: in.URL, Path: in.Path, SHA256: in.SHA256}, baseDir)
	if err != nil {
		return updater.Delta{}, err
	}
	return updater.Delta{FromVersion: strings.TrimSpace(in.FromVersion), URL: art.URL, SHA256: art.SHA256}, nil
}

func resolvePath(p string, baseDir string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" {
		return ""
	}
	if filepath.IsAbs(trimmed) {
		return trimmed
	}
	return filepath.Join(baseDir, trimmed)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	sum, err := updaterFileHash(f)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return sum, nil
}

func updaterFileHash(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func writeManifest(path string, manifest updater.Manifest) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "manifest-*.json")
	if err != nil {
		return fmt.Errorf("create temp manifest: %w", err)
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(manifest); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("encode manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("close manifest: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func writeSignature(manifestPath string, key ed25519.PrivateKey) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest for signing: %w", err)
	}
	sig := ed25519.Sign(key, data)
	sigPath := manifestPath + ".sig"
	if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)), 0o644); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	return nil
}

func loadSigningKey() (ed25519.PrivateKey, error) {
	raw := strings.TrimSpace(os.Getenv("GLYPH_UPDATER_SIGNING_KEY"))
	if raw == "" {
		return nil, errors.New("GLYPH_UPDATER_SIGNING_KEY is not set")
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode GLYPH_UPDATER_SIGNING_KEY: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("GLYPH_UPDATER_SIGNING_KEY has invalid length %d", len(decoded))
	}
	return ed25519.PrivateKey(decoded), nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
