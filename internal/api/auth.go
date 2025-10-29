package api

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Claims represents the JWT payload used for API authentication.
type Claims struct {
	Issuer      string `json:"iss"`
	Subject     string `json:"sub"`
	Audience    string `json:"aud"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	ID          string `json:"jti"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	Role        string `json:"role,omitempty"`
}

// TokenOptions customises issued JWT claims.
type TokenOptions struct {
	Audience    string
	TTL         time.Duration
	WorkspaceID string
	Role        string
}

// AuthOption mutates authenticator configuration.
type AuthOption func(*authConfig) error

type authConfig struct {
	oidc *OIDCConfig
}

// OIDCConfig configures verification against an OpenID Connect provider.
type OIDCConfig struct {
	Issuer       string
	JWKSURL      string
	Audiences    []string
	SyncInterval time.Duration
	HTTPClient   *http.Client
}

// WithOIDC enables OIDC token validation for the authenticator.
func WithOIDC(cfg OIDCConfig) AuthOption {
	return func(ac *authConfig) error {
		cfg.Issuer = strings.TrimSpace(cfg.Issuer)
		cfg.JWKSURL = strings.TrimSpace(cfg.JWKSURL)
		if cfg.Issuer == "" {
			return errors.New("oidc issuer must not be empty")
		}
		if cfg.JWKSURL == "" {
			return errors.New("oidc jwks url must not be empty")
		}
		if cfg.SyncInterval <= 0 {
			cfg.SyncInterval = 5 * time.Minute
		}
		ac.oidc = &cfg
		return nil
	}
}

// Authenticator issues and validates JWT tokens for the API.
type Authenticator struct {
	secret     []byte
	issuer     string
	defaultTTL time.Duration
	oidc       *oidcVerifier
}

// NewAuthenticator constructs an authenticator using the provided secret and issuer.
func NewAuthenticator(secret []byte, issuer string, defaultTTL time.Duration, opts ...AuthOption) (*Authenticator, error) {
	if len(secret) == 0 {
		return nil, errors.New("jwt secret must not be empty")
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, errors.New("jwt issuer must not be empty")
	}
	if defaultTTL <= 0 {
		defaultTTL = time.Hour
	}
	cfg := &authConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	var verifier *oidcVerifier
	if cfg.oidc != nil {
		v, err := newOIDCVerifier(*cfg.oidc)
		if err != nil {
			return nil, err
		}
		verifier = v
	}
	return &Authenticator{secret: secret, issuer: issuer, defaultTTL: defaultTTL, oidc: verifier}, nil
}

// Mint generates a signed JWT for the provided subject and audience.
func (a *Authenticator) Mint(subject, audience string, ttl time.Duration) (string, time.Time, error) {
	return a.MintWithOptions(subject, TokenOptions{Audience: audience, TTL: ttl})
}

// MintWithOptions generates a signed JWT using the provided options.
func (a *Authenticator) MintWithOptions(subject string, opts TokenOptions) (string, time.Time, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return "", time.Time{}, errors.New("subject is required")
	}
	audience := strings.TrimSpace(opts.Audience)
	if audience == "" {
		audience = "default"
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = a.defaultTTL
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	workspaceID := strings.TrimSpace(opts.WorkspaceID)
	role := strings.ToLower(strings.TrimSpace(opts.Role))
	now := time.Now().UTC()
	claims := Claims{
		Issuer:      a.issuer,
		Subject:     subject,
		Audience:    audience,
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(ttl).Unix(),
		ID:          uuid.NewString(),
		WorkspaceID: workspaceID,
		Role:        role,
	}
	token, err := a.sign(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, time.Unix(claims.ExpiresAt, 0).UTC(), nil
}

// Validate parses and validates a JWT, returning the embedded claims.
func (a *Authenticator) Validate(token string) (Claims, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Claims{}, errors.New("token is required")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("invalid token format")
	}
	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("decode header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Claims{}, fmt.Errorf("parse header: %w", err)
	}
	switch strings.ToUpper(strings.TrimSpace(header.Alg)) {
	case "HS256":
		return a.validateLocal(header, parts[0], parts[1], parts[2])
	case "RS256":
		if a.oidc == nil {
			return Claims{}, errors.New("oidc verifier not configured")
		}
		return a.oidc.validate(header, parts[0], parts[1], parts[2])
	default:
		return Claims{}, fmt.Errorf("unsupported alg %q", header.Alg)
	}
}

func (a *Authenticator) validateLocal(header jwtHeader, headerSeg, payloadSeg, signatureSeg string) (Claims, error) {
	if err := a.verifySignature(headerSeg, payloadSeg, signatureSeg); err != nil {
		return Claims{}, err
	}
	payloadBytes, err := decodeSegment(payloadSeg)
	if err != nil {
		return Claims{}, fmt.Errorf("decode payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return Claims{}, fmt.Errorf("parse claims: %w", err)
	}
	if claims.Issuer != a.issuer {
		return Claims{}, errors.New("issuer mismatch")
	}
	if claims.ExpiresAt <= time.Now().UTC().Unix() {
		return Claims{}, errors.New("token expired")
	}
	return claims, nil
}

func (a *Authenticator) sign(claims Claims) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("encode header: %w", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode claims: %w", err)
	}
	headerEnc := encodeSegment(headerJSON)
	payloadEnc := encodeSegment(payloadJSON)
	sigEnc, err := a.computeSignature(headerEnc, payloadEnc)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{headerEnc, payloadEnc, sigEnc}, "."), nil
}

func (a *Authenticator) verifySignature(header, payload, signature string) error {
	expected, err := a.computeSignature(header, payload)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return errors.New("invalid signature")
	}
	return nil
}

func (a *Authenticator) computeSignature(header, payload string) (string, error) {
	mac := hmac.New(sha256.New, a.secret)
	if _, err := mac.Write([]byte(header)); err != nil {
		return "", err
	}
	if _, err := mac.Write([]byte(".")); err != nil {
		return "", err
	}
	if _, err := mac.Write([]byte(payload)); err != nil {
		return "", err
	}
	sum := mac.Sum(nil)
	return encodeSegment(sum), nil
}

func encodeSegment(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type oidcVerifier struct {
	cfg       OIDCConfig
	client    *http.Client
	audiences map[string]struct{}

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	lastRefresh time.Time
}

func newOIDCVerifier(cfg OIDCConfig) (*oidcVerifier, error) {
	audMap := make(map[string]struct{}, len(cfg.Audiences))
	for _, aud := range cfg.Audiences {
		aud = strings.TrimSpace(aud)
		if aud == "" {
			continue
		}
		audMap[aud] = struct{}{}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	return &oidcVerifier{
		cfg:       cfg,
		client:    client,
		audiences: audMap,
		keys:      make(map[string]*rsa.PublicKey),
	}, nil
}

func (v *oidcVerifier) validate(header jwtHeader, headerSeg, payloadSeg, signatureSeg string) (Claims, error) {
	payloadBytes, err := decodeSegment(payloadSeg)
	if err != nil {
		return Claims{}, fmt.Errorf("decode payload: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(payloadBytes))
	dec.UseNumber()
	var payload map[string]any
	if err := dec.Decode(&payload); err != nil {
		return Claims{}, fmt.Errorf("parse payload: %w", err)
	}
	issuer := strings.TrimSpace(asString(payload["iss"]))
	if issuer != v.cfg.Issuer {
		return Claims{}, errors.New("issuer mismatch")
	}
	if !v.validateAudience(payload["aud"]) {
		return Claims{}, errors.New("audience mismatch")
	}
	exp, err := numericClaim(payload["exp"])
	if err != nil {
		return Claims{}, fmt.Errorf("parse exp: %w", err)
	}
	if time.Now().UTC().Unix() >= exp {
		return Claims{}, errors.New("token expired")
	}
	iat, err := numericClaim(payload["iat"])
	if err != nil {
		iat = time.Now().UTC().Unix()
	}
	kid := strings.TrimSpace(header.Kid)
	if kid == "" {
		return Claims{}, errors.New("missing kid")
	}
	key, err := v.publicKey(kid)
	if err != nil {
		return Claims{}, err
	}
	signed := strings.Join([]string{headerSeg, payloadSeg}, ".")
	sigBytes, err := decodeSegment(signatureSeg)
	if err != nil {
		return Claims{}, fmt.Errorf("decode signature: %w", err)
	}
	hasher := sha256.New()
	if _, err := hasher.Write([]byte(signed)); err != nil {
		return Claims{}, err
	}
	digest := hasher.Sum(nil)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, sigBytes); err != nil {
		return Claims{}, fmt.Errorf("verify signature: %w", err)
	}
	claims := Claims{
		Issuer:      issuer,
		Subject:     asString(payload["sub"]),
		Audience:    v.extractAudience(payload["aud"]),
		IssuedAt:    iat,
		ExpiresAt:   exp,
		ID:          asString(payload["jti"]),
		WorkspaceID: strings.TrimSpace(asString(payload["workspace_id"])),
		Role:        strings.ToLower(strings.TrimSpace(asString(payload["role"]))),
	}
	return claims, nil
}

func (v *oidcVerifier) validateAudience(raw any) bool {
	if len(v.audiences) == 0 {
		return true
	}
	switch val := raw.(type) {
	case string:
		_, ok := v.audiences[val]
		return ok
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok {
				if _, ok := v.audiences[s]; ok {
					return true
				}
			}
		}
	case json.Number:
		_, ok := v.audiences[val.String()]
		return ok
	}
	return false
}

func (v *oidcVerifier) extractAudience(raw any) string {
	switch val := raw.(type) {
	case string:
		return val
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok {
				return s
			}
		}
	case json.Number:
		return val.String()
	}
	return ""
}

func (v *oidcVerifier) publicKey(kid string) (*rsa.PublicKey, error) {
	now := time.Now().UTC()
	v.mu.RLock()
	key := v.keys[kid]
	refreshNeeded := now.Sub(v.lastRefresh) >= v.cfg.SyncInterval || len(v.keys) == 0
	v.mu.RUnlock()
	if key != nil && !refreshNeeded {
		return key, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	key = v.keys[kid]
	if key != nil && !refreshNeeded {
		return key, nil
	}
	if refreshNeeded || key == nil {
		if err := v.refreshKeysLocked(); err != nil {
			return nil, err
		}
		key = v.keys[kid]
	}
	if key == nil {
		return nil, fmt.Errorf("kid %s not found", kid)
	}
	return key, nil
}

func (v *oidcVerifier) refreshKeysLocked() error {
	req, err := http.NewRequest(http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return fmt.Errorf("build jwks request: %w", err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: unexpected status %s", resp.Status)
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&jwks); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if strings.ToUpper(key.Kty) != "RSA" {
			continue
		}
		modulusBytes, err := decodeSegment(key.N)
		if err != nil {
			return fmt.Errorf("decode modulus: %w", err)
		}
		exponentBytes, err := decodeSegment(key.E)
		if err != nil {
			return fmt.Errorf("decode exponent: %w", err)
		}
		exponent := 0
		if len(exponentBytes) > 0 {
			exponent = int(new(big.Int).SetBytes(exponentBytes).Int64())
		}
		if exponent == 0 {
			exponent = 65537
		}
		keys[key.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulusBytes), E: exponent}
	}
	v.keys = keys
	v.lastRefresh = time.Now().UTC()
	return nil
}

func numericClaim(value any) (int64, error) {
	switch v := value.(type) {
	case nil:
		return 0, errors.New("missing numeric claim")
	case float64:
		return int64(v), nil
	case json.Number:
		return v.Int64()
	case string:
		if strings.TrimSpace(v) == "" {
			return 0, errors.New("empty numeric claim")
		}
		return strconv.ParseInt(v, 10, 64)
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("unsupported numeric claim type %T", value)
	}
}

func asString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		return ""
	}
}
