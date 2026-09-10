package api

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents the JWT payload used for API authentication.
type Claims struct {
	Issuer      string `json:"iss"`
	Subject     string `json:"sub"`
	Audience    string `json:"aud"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	NotBefore   int64  `json:"nbf,omitempty"`
	ID          string `json:"jti"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	Role        string `json:"role,omitempty"`
}

// The methods below satisfy jwt.Claims so Claims can be used directly with
// golang-jwt/jwt/v5's signing and parsing APIs.

func (c Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

func (c Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

func (c Claims) GetNotBefore() (*jwt.NumericDate, error) {
	if c.NotBefore == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.NotBefore, 0)), nil
}

func (c Claims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c Claims) GetSubject() (string, error) {
	return c.Subject, nil
}

func (c Claims) GetAudience() (jwt.ClaimStrings, error) {
	if c.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{c.Audience}, nil
}

// TokenOptions customises issued JWT claims.
type TokenOptions struct {
	Audience    string
	TTL         time.Duration
	WorkspaceID string
	Role        string
	NotBefore   time.Time
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
	var notBefore int64
	if !opts.NotBefore.IsZero() {
		notBefore = opts.NotBefore.UTC().Unix()
	}
	claims := Claims{
		Issuer:      a.issuer,
		Subject:     subject,
		Audience:    audience,
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(ttl).Unix(),
		NotBefore:   notBefore,
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
// expectedAudience, when non-empty, must match the token's "aud" claim on
// the local HS256 path or the token is rejected.
func (a *Authenticator) Validate(tokenString, expectedAudience string) (Claims, error) {
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return Claims{}, errors.New("token is required")
	}
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return Claims{}, fmt.Errorf("parse token: %w", err)
	}
	if typ, ok := unverified.Header["typ"].(string); ok && typ != "" && !strings.EqualFold(typ, "JWT") {
		return Claims{}, fmt.Errorf("unsupported typ %q", typ)
	}
	switch unverified.Method.Alg() {
	case "HS256":
		return a.validateLocal(tokenString, expectedAudience)
	case "RS256":
		if a.oidc == nil {
			return Claims{}, errors.New("oidc verifier not configured")
		}
		return a.oidc.validate(tokenString)
	default:
		return Claims{}, fmt.Errorf("unsupported alg %q", unverified.Method.Alg())
	}
}

func (a *Authenticator) validateLocal(tokenString, expectedAudience string) (Claims, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(a.issuer),
		jwt.WithExpirationRequired(),
	}
	expectedAudience = strings.TrimSpace(expectedAudience)
	if expectedAudience != "" {
		opts = append(opts, jwt.WithAudience(expectedAudience))
	}
	var claims Claims
	if _, err := jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (any, error) {
		return a.secret, nil
	}, opts...); err != nil {
		return Claims{}, err
	}
	claims.Role = strings.ToLower(strings.TrimSpace(claims.Role))
	claims.WorkspaceID = strings.TrimSpace(claims.WorkspaceID)
	return claims, nil
}

func (a *Authenticator) sign(claims Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.secret)
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

func (v *oidcVerifier) validate(tokenString string) (Claims, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithExpirationRequired(),
	}
	if len(v.audiences) > 0 {
		auds := make([]string, 0, len(v.audiences))
		for aud := range v.audiences {
			auds = append(auds, aud)
		}
		opts = append(opts, jwt.WithAudience(auds...))
	}
	var claims Claims
	_, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		kid = strings.TrimSpace(kid)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return v.publicKey(kid)
	}, opts...)
	if err != nil {
		return Claims{}, err
	}
	claims.Role = strings.ToLower(strings.TrimSpace(claims.Role))
	claims.WorkspaceID = strings.TrimSpace(claims.WorkspaceID)
	return claims, nil
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
		modulusBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return fmt.Errorf("decode modulus: %w", err)
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(key.E)
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
