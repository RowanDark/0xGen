package reporter

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// SignArtifact generates a detached cosign-compatible signature alongside the report artifact.
func SignArtifact(artifactPath, keyPath string) (string, error) {
	artifactPath = strings.TrimSpace(artifactPath)
	keyPath = strings.TrimSpace(keyPath)
	if artifactPath == "" {
		return "", errors.New("artifact path is required")
	}
	if keyPath == "" {
		return "", errors.New("signing key path is required")
	}

	digest, err := computeFileDigest(artifactPath)
	if err != nil {
		return "", fmt.Errorf("hash artifact: %w", err)
	}

	privateKey, err := loadSigningKey(keyPath)
	if err != nil {
		return "", err
	}

	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	if err != nil {
		return "", fmt.Errorf("sign artifact: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(signature)
	signaturePath := artifactPath + ".sig"
	if err := os.WriteFile(signaturePath, []byte(encoded+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write signature: %w", err)
	}
	return signaturePath, nil
}

func loadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("decode signing key: missing PEM block")
	}
	if strings.Contains(strings.ToUpper(block.Type), "ENCRYPTED") {
		return nil, errors.New("encrypted signing keys are not supported; export an unencrypted key with cosign sign-blob --key")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		ec, parseErr := x509.ParseECPrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse ec private key: %w", parseErr)
		}
		return ec, nil
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse pkcs8 private key: %w", parseErr)
		}
		ec, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("pkcs8 key is %T, expected *ecdsa.PrivateKey", parsed)
		}
		return ec, nil
	default:
		return nil, fmt.Errorf("unsupported signing key type %q", block.Type)
	}
}

// ComputeBundleDigest calculates the SHA-256 digest for the provided bytes in hex form.
func ComputeBundleDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum[:])
}

// ComputeFileDigestHex returns the SHA-256 digest for the file at the provided path.
func ComputeFileDigestHex(path string) (string, error) {
	digest, err := computeFileDigest(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", digest), nil
}
