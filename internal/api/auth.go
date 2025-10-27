package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Claims represents the JWT payload used for API authentication.
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	ID        string `json:"jti"`
}

// Authenticator issues and validates JWT tokens for the API.
type Authenticator struct {
	secret     []byte
	issuer     string
	defaultTTL time.Duration
}

// NewAuthenticator constructs an authenticator using the provided secret and issuer.
func NewAuthenticator(secret []byte, issuer string, defaultTTL time.Duration) (*Authenticator, error) {
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
	return &Authenticator{secret: secret, issuer: issuer, defaultTTL: defaultTTL}, nil
}

// Mint generates a signed JWT for the provided subject and audience.
func (a *Authenticator) Mint(subject, audience string, ttl time.Duration) (string, time.Time, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return "", time.Time{}, errors.New("subject is required")
	}
	audience = strings.TrimSpace(audience)
	if audience == "" {
		audience = "default"
	}
	if ttl <= 0 {
		ttl = a.defaultTTL
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()
	claims := Claims{
		Issuer:    a.issuer,
		Subject:   subject,
		Audience:  audience,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		ID:        uuid.NewString(),
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
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Claims{}, fmt.Errorf("parse header: %w", err)
	}
	if strings.ToUpper(header.Alg) != "HS256" {
		return Claims{}, fmt.Errorf("unsupported alg %q", header.Alg)
	}
	payloadBytes, err := decodeSegment(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("decode payload: %w", err)
	}
	if err := a.verifySignature(parts[0], parts[1], parts[2]); err != nil {
		return Claims{}, err
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return Claims{}, fmt.Errorf("parse claims: %w", err)
	}
	if claims.Issuer != a.issuer {
		return Claims{}, errors.New("issuer mismatch")
	}
	now := time.Now().UTC().Unix()
	if claims.ExpiresAt <= now {
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
