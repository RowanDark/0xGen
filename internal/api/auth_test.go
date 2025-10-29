package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMintWithOptionsIncludesWorkspaceClaims(t *testing.T) {
	auth, err := NewAuthenticator([]byte("secret"), "issuer", time.Minute)
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}
	token, _, err := auth.MintWithOptions("user-1", TokenOptions{
		Audience:    "aud",
		WorkspaceID: "workspace-1",
		Role:        "Admin",
	})
	if err != nil {
		t.Fatalf("MintWithOptions failed: %v", err)
	}
	claims, err := auth.Validate(token)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if claims.WorkspaceID != "workspace-1" {
		t.Fatalf("expected workspace id workspace-1, got %q", claims.WorkspaceID)
	}
	if claims.Role != "admin" {
		t.Fatalf("expected role to normalise to admin, got %q", claims.Role)
	}
}

func TestAuthenticatorValidatesOIDCTokens(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	kid := "test-key"
	jwks := struct {
		Keys []map[string]string `json:"keys"`
	}{
		Keys: []map[string]string{{
			"kty": "RSA",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(bigIntBytes(int64(key.PublicKey.E))),
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	issuer := "https://issuer.example"
	auth, err := NewAuthenticator([]byte("local-secret"), "local", time.Minute, WithOIDC(OIDCConfig{
		Issuer:     issuer,
		JWKSURL:    srv.URL,
		Audiences:  []string{"oidc-aud"},
		HTTPClient: srv.Client(),
	}))
	if err != nil {
		t.Fatalf("NewAuthenticator with OIDC failed: %v", err)
	}

	payload := map[string]any{
		"iss":          issuer,
		"aud":          "oidc-aud",
		"exp":          time.Now().Add(5 * time.Minute).Unix(),
		"iat":          time.Now().Unix(),
		"sub":          "user-oidc",
		"jti":          "token-1",
		"workspace_id": "workspace-oidc",
		"role":         "Analyst",
	}
	token, err := signOIDCToken(key, kid, payload)
	if err != nil {
		t.Fatalf("signOIDCToken failed: %v", err)
	}
	claims, err := auth.Validate(token)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if claims.Subject != "user-oidc" {
		t.Fatalf("unexpected subject: %q", claims.Subject)
	}
	if claims.WorkspaceID != "workspace-oidc" {
		t.Fatalf("unexpected workspace: %q", claims.WorkspaceID)
	}
	if claims.Role != "analyst" {
		t.Fatalf("role normalisation failed, got %q", claims.Role)
	}
}

func signOIDCToken(key *rsa.PrivateKey, kid string, payload map[string]any) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	headerSeg := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadSeg := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signing := headerSeg + "." + payloadSeg
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	sigSeg := base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join([]string{headerSeg, payloadSeg, sigSeg}, "."), nil
}

func bigIntBytes(v int64) []byte {
	b := make([]byte, 0, 8)
	for v > 0 {
		b = append([]byte{byte(v & 0xff)}, b...)
		v >>= 8
	}
	if len(b) == 0 {
		return []byte{0x01, 0x00, 0x01}
	}
	return b
}
