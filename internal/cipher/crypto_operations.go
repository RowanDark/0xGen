package cipher

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Gzip Compression Operations

// GzipCompressOp compresses data using gzip
type GzipCompressOp struct {
	BaseOperation
}

func (op *GzipCompressOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	if _, err := writer.Write(input); err != nil {
		return nil, fmt.Errorf("gzip write failed: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("gzip close failed: %w", err)
	}

	return buf.Bytes(), nil
}

// GzipDecompressOp decompresses gzip data
type GzipDecompressOp struct {
	BaseOperation
}

func (op *GzipDecompressOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(input))
	if err != nil {
		return nil, fmt.Errorf("gzip reader failed: %w", err)
	}
	defer reader.Close()

	output, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("gzip read failed: %w", err)
	}

	return output, nil
}

// Hash Operations

// MD5HashOp computes MD5 hash
type MD5HashOp struct {
	BaseOperation
}

func (op *MD5HashOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	hash := md5.Sum(input)
	return []byte(hex.EncodeToString(hash[:])), nil
}

// SHA1HashOp computes SHA-1 hash
type SHA1HashOp struct {
	BaseOperation
}

func (op *SHA1HashOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	hash := sha1.Sum(input)
	return []byte(hex.EncodeToString(hash[:])), nil
}

// SHA256HashOp computes SHA-256 hash
type SHA256HashOp struct {
	BaseOperation
}

func (op *SHA256HashOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	hash := sha256.Sum256(input)
	return []byte(hex.EncodeToString(hash[:])), nil
}

// SHA512HashOp computes SHA-512 hash
type SHA512HashOp struct {
	BaseOperation
}

func (op *SHA512HashOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	hash := sha512.Sum512(input)
	return []byte(hex.EncodeToString(hash[:])), nil
}

// JWT Operations

// JWTDecodeOp decodes a JWT token and displays its header and payload
type JWTDecodeOp struct {
	BaseOperation
}

func (op *JWTDecodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	tokenString := strings.TrimSpace(string(input))

	// Parse without verification to examine contents
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("jwt parse failed: %w", err)
	}

	// Extract header
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt format: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header decode failed: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerData, &header); err != nil {
		return nil, fmt.Errorf("header unmarshal failed: %w", err)
	}

	// Format output
	result := map[string]interface{}{
		"header":    header,
		"payload":   token.Claims,
		"signature": parts[2],
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("output marshal failed: %w", err)
	}

	return output, nil
}

// JWTVerifyOp verifies a JWT token with a secret or public key
type JWTVerifyOp struct {
	BaseOperation
}

func (op *JWTVerifyOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	tokenString := strings.TrimSpace(string(input))

	// Get secret from params
	secret, ok := params["secret"].(string)
	if !ok || secret == "" {
		return nil, fmt.Errorf("secret parameter required for JWT verification")
	}

	// Parse and verify
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("jwt verification failed: %w", err)
	}

	if !token.Valid {
		return []byte("INVALID"), nil
	}

	// Return pretty-printed claims
	claims, err := json.MarshalIndent(token.Claims, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("claims marshal failed: %w", err)
	}

	result := map[string]interface{}{
		"valid":  true,
		"claims": json.RawMessage(claims),
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("output marshal failed: %w", err)
	}

	return output, nil
}

// JWTSignOp creates a signed JWT token
type JWTSignOp struct {
	BaseOperation
}

func (op *JWTSignOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	// Parse input as JSON claims
	var claims jwt.MapClaims
	if err := json.Unmarshal(input, &claims); err != nil {
		return nil, fmt.Errorf("claims must be valid JSON: %w", err)
	}

	// Get secret from params
	secret, ok := params["secret"].(string)
	if !ok || secret == "" {
		return nil, fmt.Errorf("secret parameter required for JWT signing")
	}

	// Get algorithm from params (default HS256)
	algorithm := "HS256"
	if alg, ok := params["algorithm"].(string); ok {
		algorithm = alg
	}

	// Set default expiration if not provided
	if _, hasExp := claims["exp"]; !hasExp {
		// Default to 1 hour from now
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}

	// Set issued at if not provided
	if _, hasIat := claims["iat"]; !hasIat {
		claims["iat"] = time.Now().Unix()
	}

	// Create token
	var method jwt.SigningMethod
	switch algorithm {
	case "HS256":
		method = jwt.SigningMethodHS256
	case "HS384":
		method = jwt.SigningMethodHS384
	case "HS512":
		method = jwt.SigningMethodHS512
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	token := jwt.NewWithClaims(method, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return nil, fmt.Errorf("jwt signing failed: %w", err)
	}

	return []byte(tokenString), nil
}

// init registers compression and crypto operations
func init() {
	// Gzip operations
	gzipCompress := &GzipCompressOp{
		BaseOperation: BaseOperation{
			NameValue:        "gzip_compress",
			TypeValue:        OperationTypeCompress,
			DescriptionValue: "Compress data using gzip",
		},
	}
	gzipDecompress := &GzipDecompressOp{
		BaseOperation: BaseOperation{
			NameValue:        "gzip_decompress",
			TypeValue:        OperationTypeDecompress,
			DescriptionValue: "Decompress gzip data",
		},
	}
	gzipCompress.ReverseOp = gzipDecompress
	gzipDecompress.ReverseOp = gzipCompress

	// Hash operations (not reversible)
	md5Hash := &MD5HashOp{
		BaseOperation: BaseOperation{
			NameValue:        "md5_hash",
			TypeValue:        OperationTypeHash,
			DescriptionValue: "Compute MD5 hash",
		},
	}

	sha1Hash := &SHA1HashOp{
		BaseOperation: BaseOperation{
			NameValue:        "sha1_hash",
			TypeValue:        OperationTypeHash,
			DescriptionValue: "Compute SHA-1 hash",
		},
	}

	sha256Hash := &SHA256HashOp{
		BaseOperation: BaseOperation{
			NameValue:        "sha256_hash",
			TypeValue:        OperationTypeHash,
			DescriptionValue: "Compute SHA-256 hash",
		},
	}

	sha512Hash := &SHA512HashOp{
		BaseOperation: BaseOperation{
			NameValue:        "sha512_hash",
			TypeValue:        OperationTypeHash,
			DescriptionValue: "Compute SHA-512 hash",
		},
	}

	// JWT operations
	jwtDecode := &JWTDecodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "jwt_decode",
			TypeValue:        OperationTypeDecode,
			DescriptionValue: "Decode JWT token (without verification)",
		},
	}

	jwtVerify := &JWTVerifyOp{
		BaseOperation: BaseOperation{
			NameValue:        "jwt_verify",
			TypeValue:        OperationTypeDecode,
			DescriptionValue: "Verify JWT token with secret",
		},
	}

	jwtSign := &JWTSignOp{
		BaseOperation: BaseOperation{
			NameValue:        "jwt_sign",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "Sign JWT token with secret",
		},
	}

	// Register all operations
	RegisterOperation(gzipCompress)
	RegisterOperation(gzipDecompress)
	RegisterOperation(md5Hash)
	RegisterOperation(sha1Hash)
	RegisterOperation(sha256Hash)
	RegisterOperation(sha512Hash)
	RegisterOperation(jwtDecode)
	RegisterOperation(jwtVerify)
	RegisterOperation(jwtSign)
}
