package integrity

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/RowanDark/0xgen/internal/plugins"
)

// VerifySignature validates a detached signature created with cosign's ECDSA
// signing mode against the provided artifact. All paths are resolved relative
// to the manifest directory and, if necessary, the repository root.
func VerifySignature(artifactPath, manifestDir, repoRoot string, sig *plugins.Signature) error {
	if sig == nil {
		return errors.New("signature metadata missing")
	}

	signaturePath, err := resolvePath(sig.Signature, manifestDir, repoRoot)
	if err != nil {
		return fmt.Errorf("resolve signature: %w", err)
	}
	signatureBytes, err := loadSignature(signaturePath)
	if err != nil {
		return err
	}

	pubKey, err := loadPublicKey(sig, manifestDir, repoRoot)
	if err != nil {
		return err
	}

	digest, err := fileDigest(artifactPath)
	if err != nil {
		return err
	}

	if !ecdsa.VerifyASN1(pubKey, digest, signatureBytes) {
		return errors.New("signature verification failed")
	}
	return nil
}

func resolvePath(path, manifestDir, repoRoot string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("empty path")
	}
	if filepath.IsAbs(path) {
		return path, nil
	}
	candidates := []string{}
	if manifestDir != "" {
		candidates = append(candidates, filepath.Join(manifestDir, path))
	}
	if repoRoot != "" {
		candidates = append(candidates, filepath.Join(repoRoot, path))
	}
	cleaned := filepath.Clean(path)
	if cleaned != path {
		if manifestDir != "" {
			candidates = append(candidates, filepath.Join(manifestDir, cleaned))
		}
		if repoRoot != "" {
			candidates = append(candidates, filepath.Join(repoRoot, cleaned))
		}
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("path %q could not be resolved relative to manifest or repository", path)
}

func loadSignature(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("signature is empty")
	}
	return data, nil
}

func loadPublicKey(sig *plugins.Signature, manifestDir, repoRoot string) (*ecdsa.PublicKey, error) {
	if strings.TrimSpace(sig.Certificate) != "" {
		certPath, err := resolvePath(sig.Certificate, manifestDir, repoRoot)
		if err != nil {
			return nil, fmt.Errorf("resolve certificate: %w", err)
		}
		key, err := certificatePublicKey(certPath)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	if strings.TrimSpace(sig.PublicKey) != "" {
		keyPath, err := resolvePath(sig.PublicKey, manifestDir, repoRoot)
		if err != nil {
			return nil, fmt.Errorf("resolve public key: %w", err)
		}
		raw, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read public key: %w", err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("decode public key: missing PEM block")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key type %T is not supported", parsed)
		}
		return pub, nil
	}
	return nil, errors.New("signature metadata does not specify a certificate or public key")
}

func certificatePublicKey(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	var block *pem.Block
	for {
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("certificate public key type %T is not supported", cert.PublicKey)
			}
			return pub, nil
		}
	}
	return nil, errors.New("certificate does not contain a supported public key")
}

func fileDigest(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open artifact: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return nil, fmt.Errorf("hash artifact: %w", err)
	}
	sum := h.Sum(nil)
	return sum, nil
}
