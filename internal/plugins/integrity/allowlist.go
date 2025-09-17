package integrity

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Allowlist captures the trusted hashes recorded for plugin artifacts.
type Allowlist struct {
	baseDir string
	entries map[string]string
}

// LoadAllowlist parses the allowlist file. Paths are interpreted relative to
// the directory containing the allowlist itself.
func LoadAllowlist(path string) (*Allowlist, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open allowlist: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	entries := make(map[string]string)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid allowlist entry on line %d", lineNo)
		}
		hash := strings.ToLower(fields[0])
		if len(hash) != 64 {
			return nil, fmt.Errorf("invalid hash on line %d", lineNo)
		}
		pathField := filepath.ToSlash(filepath.Clean(fields[1]))
		entries[pathField] = hash
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}

	return &Allowlist{baseDir: filepath.Dir(path), entries: entries}, nil
}

// Verify ensures the artifact's hash matches the allowlist.
func (a *Allowlist) Verify(artifactPath string) error {
	if a == nil {
		return errors.New("allowlist not initialised")
	}
	abs, err := filepath.Abs(artifactPath)
	if err != nil {
		return fmt.Errorf("abs artifact path: %w", err)
	}
	rel, err := filepath.Rel(a.baseDir, abs)
	if err != nil {
		return fmt.Errorf("relativise artifact: %w", err)
	}
	key := filepath.ToSlash(rel)

	expected, ok := a.entries[key]
	if !ok {
		return fmt.Errorf("artifact %s not present in allowlist", key)
	}

	actual, err := hashFile(abs)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("artifact %s hash mismatch", key)
	}
	return nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open artifact: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("hash artifact: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashFile exposes the SHA-256 helper for external callers.
func HashFile(path string) (string, error) {
	return hashFile(path)
}
