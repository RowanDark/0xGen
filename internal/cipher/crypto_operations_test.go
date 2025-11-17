package cipher

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestGzipOperations(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"simple text", "Hello, World!"},
		{"long text", strings.Repeat("This is a test. ", 100)},
		{"empty", ""},
		{"unicode", "Hello 世界 🌍"},
	}

	ctx := context.Background()
	compress, _ := GetOperation("gzip_compress")
	decompress, _ := GetOperation("gzip_decompress")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compress
			compressed, err := compress.Execute(ctx, []byte(tt.input), nil)
			if err != nil {
				t.Fatalf("compress failed: %v", err)
			}

			// Verify compression happened (except for empty string)
			if len(tt.input) > 10 && len(compressed) >= len(tt.input) {
				t.Logf("Warning: compressed size (%d) >= input size (%d)", len(compressed), len(tt.input))
			}

			// Decompress
			decompressed, err := decompress.Execute(ctx, compressed, nil)
			if err != nil {
				t.Fatalf("decompress failed: %v", err)
			}

			if string(decompressed) != tt.input {
				t.Errorf("roundtrip failed: expected %q, got %q", tt.input, string(decompressed))
			}
		})
	}
}

func TestHashOperations(t *testing.T) {
	tests := []struct {
		operation string
		input     string
		expected  string
	}{
		{"md5_hash", "hello", "5d41402abc4b2a76b9719d911017c592"},
		{"sha1_hash", "hello", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
		{"sha256_hash", "hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		{"sha512_hash", "hello", "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			op, exists := GetOperation(tt.operation)
			if !exists {
				t.Fatalf("operation %s not found", tt.operation)
			}

			result, err := op.Execute(ctx, []byte(tt.input), nil)
			if err != nil {
				t.Fatalf("hash failed: %v", err)
			}

			if string(result) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, string(result))
			}
		})
	}
}

func TestHashOperationsNotReversible(t *testing.T) {
	hashOps := []string{"md5_hash", "sha1_hash", "sha256_hash", "sha512_hash"}

	for _, opName := range hashOps {
		t.Run(opName, func(t *testing.T) {
			op, _ := GetOperation(opName)
			_, reversible := op.Reverse()
			if reversible {
				t.Errorf("hash operation %s should not be reversible", opName)
			}
		})
	}
}

func TestJWTDecode(t *testing.T) {
	// Sample JWT (from jwt.io)
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	ctx := context.Background()
	decoder, _ := GetOperation("jwt_decode")

	result, err := decoder.Execute(ctx, []byte(token), nil)
	if err != nil {
		t.Fatalf("jwt_decode failed: %v", err)
	}

	// Parse result as JSON
	var decoded map[string]interface{}
	if err := json.Unmarshal(result, &decoded); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	// Verify structure
	if _, hasHeader := decoded["header"]; !hasHeader {
		t.Error("decoded result missing header")
	}
	if _, hasPayload := decoded["payload"]; !hasPayload {
		t.Error("decoded result missing payload")
	}
	if _, hasSignature := decoded["signature"]; !hasSignature {
		t.Error("decoded result missing signature")
	}

	// Verify payload contains expected claims
	payload, ok := decoded["payload"].(map[string]interface{})
	if !ok {
		t.Fatal("payload is not an object")
	}

	if payload["sub"] != "1234567890" {
		t.Errorf("expected sub=1234567890, got %v", payload["sub"])
	}
}

func TestJWTVerify(t *testing.T) {
	secret := "your-256-bit-secret"
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	ctx := context.Background()
	verifier, _ := GetOperation("jwt_verify")

	params := map[string]interface{}{
		"secret": secret,
	}

	result, err := verifier.Execute(ctx, []byte(token), params)
	if err != nil {
		t.Fatalf("jwt_verify failed: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(result, &decoded); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	if valid, ok := decoded["valid"].(bool); !ok || !valid {
		t.Error("token should be valid")
	}
}

func TestJWTVerifyInvalidSecret(t *testing.T) {
	wrongSecret := "wrong-secret"
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	ctx := context.Background()
	verifier, _ := GetOperation("jwt_verify")

	params := map[string]interface{}{
		"secret": wrongSecret,
	}

	_, err := verifier.Execute(ctx, []byte(token), params)
	if err == nil {
		t.Error("expected verification to fail with wrong secret")
	}
}

func TestJWTSign(t *testing.T) {
	ctx := context.Background()
	signer, _ := GetOperation("jwt_sign")

	claims := map[string]interface{}{
		"sub":  "1234567890",
		"name": "Jane Doe",
		"admin": true,
	}

	claimsJSON, _ := json.Marshal(claims)
	params := map[string]interface{}{
		"secret": "test-secret",
	}

	result, err := signer.Execute(ctx, claimsJSON, params)
	if err != nil {
		t.Fatalf("jwt_sign failed: %v", err)
	}

	tokenString := string(result)

	// Verify it's a valid JWT structure (3 parts separated by dots)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts in JWT, got %d", len(parts))
	}

	// Verify we can decode it
	decoder, _ := GetOperation("jwt_decode")
	decoded, err := decoder.Execute(ctx, result, nil)
	if err != nil {
		t.Fatalf("failed to decode signed token: %v", err)
	}

	var decodedResult map[string]interface{}
	if err := json.Unmarshal(decoded, &decodedResult); err != nil {
		t.Fatalf("decoded result is not valid JSON: %v", err)
	}

	payload, ok := decodedResult["payload"].(map[string]interface{})
	if !ok {
		t.Fatal("payload is not an object")
	}

	if payload["sub"] != "1234567890" {
		t.Errorf("expected sub=1234567890, got %v", payload["sub"])
	}
	if payload["name"] != "Jane Doe" {
		t.Errorf("expected name=Jane Doe, got %v", payload["name"])
	}
}

func TestJWTSignAndVerifyRoundtrip(t *testing.T) {
	ctx := context.Background()
	signer, _ := GetOperation("jwt_sign")
	verifier, _ := GetOperation("jwt_verify")

	secret := "roundtrip-secret"
	claims := map[string]interface{}{
		"user": "test@example.com",
		"role": "admin",
	}

	claimsJSON, _ := json.Marshal(claims)
	params := map[string]interface{}{
		"secret": secret,
	}

	// Sign
	token, err := signer.Execute(ctx, claimsJSON, params)
	if err != nil {
		t.Fatalf("jwt_sign failed: %v", err)
	}

	// Verify
	verifyParams := map[string]interface{}{
		"secret": secret,
	}
	result, err := verifier.Execute(ctx, token, verifyParams)
	if err != nil {
		t.Fatalf("jwt_verify failed: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(result, &decoded); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	if valid, ok := decoded["valid"].(bool); !ok || !valid {
		t.Error("token should be valid")
	}
}
