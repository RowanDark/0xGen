package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func computeDigest(data []byte, algorithm string) (string, error) {
	alg := strings.TrimSpace(strings.ToLower(algorithm))
	if alg == "" {
		alg = "sha256"
	}
	switch alg {
	case "sha256":
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}
}
