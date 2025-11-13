package cipher

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"strconv"
	"strings"
)

// Base64 Operations

// Base64EncodeOp encodes data as standard Base64
type Base64EncodeOp struct {
	BaseOperation
}

func (op *Base64EncodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(input)
	return []byte(encoded), nil
}

// Base64DecodeOp decodes standard Base64 data
type Base64DecodeOp struct {
	BaseOperation
}

func (op *Base64DecodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(input))
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}
	return decoded, nil
}

// Base64URLEncodeOp encodes data as URL-safe Base64
type Base64URLEncodeOp struct {
	BaseOperation
}

func (op *Base64URLEncodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	encoded := base64.URLEncoding.EncodeToString(input)
	return []byte(encoded), nil
}

// Base64URLDecodeOp decodes URL-safe Base64 data
type Base64URLDecodeOp struct {
	BaseOperation
}

func (op *Base64URLDecodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	decoded, err := base64.URLEncoding.DecodeString(string(input))
	if err != nil {
		// Try with RawURLEncoding (no padding)
		decoded, err = base64.RawURLEncoding.DecodeString(string(input))
		if err != nil {
			return nil, fmt.Errorf("base64url decode failed: %w", err)
		}
	}
	return decoded, nil
}

// URL Encoding Operations

// URLEncodeOp encodes data as URL-encoded (percent-encoded) string
type URLEncodeOp struct {
	BaseOperation
}

func (op *URLEncodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	encoded := url.QueryEscape(string(input))
	return []byte(encoded), nil
}

// URLDecodeOp decodes URL-encoded (percent-encoded) string
type URLDecodeOp struct {
	BaseOperation
}

func (op *URLDecodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	decoded, err := url.QueryUnescape(string(input))
	if err != nil {
		return nil, fmt.Errorf("url decode failed: %w", err)
	}
	return []byte(decoded), nil
}

// HTML Entity Operations

// HTMLEncodeOp encodes special characters as HTML entities
type HTMLEncodeOp struct {
	BaseOperation
}

func (op *HTMLEncodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	encoded := html.EscapeString(string(input))
	return []byte(encoded), nil
}

// HTMLDecodeOp decodes HTML entities to their character equivalents
type HTMLDecodeOp struct {
	BaseOperation
}

func (op *HTMLDecodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	decoded := html.UnescapeString(string(input))
	return []byte(decoded), nil
}

// Hex Operations

// HexEncodeOp encodes bytes as hexadecimal string
type HexEncodeOp struct {
	BaseOperation
}

func (op *HexEncodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	encoded := hex.EncodeToString(input)
	return []byte(encoded), nil
}

// HexDecodeOp decodes hexadecimal string to bytes
type HexDecodeOp struct {
	BaseOperation
}

func (op *HexDecodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	// Remove common prefixes
	inputStr := string(input)
	inputStr = strings.TrimPrefix(inputStr, "0x")
	inputStr = strings.TrimPrefix(inputStr, "\\x")
	inputStr = strings.ReplaceAll(inputStr, " ", "")
	inputStr = strings.ReplaceAll(inputStr, ":", "")
	inputStr = strings.ReplaceAll(inputStr, "-", "")

	decoded, err := hex.DecodeString(inputStr)
	if err != nil {
		return nil, fmt.Errorf("hex decode failed: %w", err)
	}
	return decoded, nil
}

// Binary Operations

// BinaryEncodeOp encodes bytes as binary string (0s and 1s)
type BinaryEncodeOp struct {
	BaseOperation
}

func (op *BinaryEncodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	for i, b := range input {
		if i > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(fmt.Sprintf("%08b", b))
	}
	return buf.Bytes(), nil
}

// BinaryDecodeOp decodes binary string to bytes
type BinaryDecodeOp struct {
	BaseOperation
}

func (op *BinaryDecodeOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	// Remove spaces and split into 8-bit chunks
	inputStr := strings.ReplaceAll(string(input), " ", "")
	inputStr = strings.TrimSpace(inputStr)

	if len(inputStr)%8 != 0 {
		return nil, fmt.Errorf("binary string length must be multiple of 8, got %d", len(inputStr))
	}

	result := make([]byte, 0, len(inputStr)/8)
	for i := 0; i < len(inputStr); i += 8 {
		chunk := inputStr[i : i+8]
		val, err := strconv.ParseUint(chunk, 2, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid binary string at position %d: %w", i, err)
		}
		result = append(result, byte(val))
	}

	return result, nil
}

// ASCII Hex Operations (for displaying hex as ASCII and vice versa)

// ASCIIToHexOp converts ASCII text to hex representation
type ASCIIToHexOp struct {
	BaseOperation
}

func (op *ASCIIToHexOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	for i, b := range input {
		if i > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(fmt.Sprintf("%02x", b))
	}
	return buf.Bytes(), nil
}

// HexToASCIIOp converts hex representation to ASCII text
type HexToASCIIOp struct {
	BaseOperation
}

func (op *HexToASCIIOp) Execute(ctx context.Context, input []byte, params map[string]interface{}) ([]byte, error) {
	// This is essentially the same as HexDecode
	return (&HexDecodeOp{}).Execute(ctx, input, params)
}

// init registers all basic encoding/decoding operations
func init() {
	// Base64 operations
	base64Encode := &Base64EncodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "base64_encode",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "Encode data as standard Base64",
		},
	}
	base64Decode := &Base64DecodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "base64_decode",
			TypeValue:        OperationTypeDecode,
			DescriptionValue: "Decode standard Base64 data",
		},
	}
	base64Encode.ReverseOp = base64Decode
	base64Decode.ReverseOp = base64Encode

	// Base64 URL operations
	base64URLEncode := &Base64URLEncodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "base64url_encode",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "Encode data as URL-safe Base64",
		},
	}
	base64URLDecode := &Base64URLDecodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "base64url_decode",
			TypeValue:        OperationTypeDecode,
			DescriptionValue: "Decode URL-safe Base64 data",
		},
	}
	base64URLEncode.ReverseOp = base64URLDecode
	base64URLDecode.ReverseOp = base64URLEncode

	// URL encoding operations
	urlEncode := &URLEncodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "url_encode",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "URL encode (percent-encode) data",
		},
	}
	urlDecode := &URLDecodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "url_decode",
			TypeValue:        OperationTypeDecode,
			DescriptionValue: "URL decode (percent-decode) data",
		},
	}
	urlEncode.ReverseOp = urlDecode
	urlDecode.ReverseOp = urlEncode

	// HTML entity operations
	htmlEncode := &HTMLEncodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "html_encode",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "Encode special characters as HTML entities",
		},
	}
	htmlDecode := &HTMLDecodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "html_decode",
			TypeValue:        OperationTypeDecode,
			DescriptionValue: "Decode HTML entities",
		},
	}
	htmlEncode.ReverseOp = htmlDecode
	htmlDecode.ReverseOp = htmlEncode

	// Hex operations
	hexEncode := &HexEncodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "hex_encode",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "Encode bytes as hexadecimal string",
		},
	}
	hexDecode := &HexDecodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "hex_decode",
			TypeValue:        OperationTypeDecode,
			DescriptionValue: "Decode hexadecimal string to bytes",
		},
	}
	hexEncode.ReverseOp = hexDecode
	hexDecode.ReverseOp = hexEncode

	// Binary operations
	binaryEncode := &BinaryEncodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "binary_encode",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "Encode bytes as binary string",
		},
	}
	binaryDecode := &BinaryDecodeOp{
		BaseOperation: BaseOperation{
			NameValue:        "binary_decode",
			TypeValue:        OperationTypeDecode,
			DescriptionValue: "Decode binary string to bytes",
		},
	}
	binaryEncode.ReverseOp = binaryDecode
	binaryDecode.ReverseOp = binaryEncode

	// ASCII/Hex operations
	asciiToHex := &ASCIIToHexOp{
		BaseOperation: BaseOperation{
			NameValue:        "ascii_to_hex",
			TypeValue:        OperationTypeEncode,
			DescriptionValue: "Convert ASCII to hex representation",
		},
	}
	hexToASCII := &HexToASCIIOp{
		BaseOperation: BaseOperation{
			NameValue:        "hex_to_ascii",
			TypeValue:        OperationTypeDecode,
			DescriptionValue: "Convert hex to ASCII representation",
		},
	}
	asciiToHex.ReverseOp = hexToASCII
	hexToASCII.ReverseOp = asciiToHex

	// Register all operations
	RegisterOperation(base64Encode)
	RegisterOperation(base64Decode)
	RegisterOperation(base64URLEncode)
	RegisterOperation(base64URLDecode)
	RegisterOperation(urlEncode)
	RegisterOperation(urlDecode)
	RegisterOperation(htmlEncode)
	RegisterOperation(htmlDecode)
	RegisterOperation(hexEncode)
	RegisterOperation(hexDecode)
	RegisterOperation(binaryEncode)
	RegisterOperation(binaryDecode)
	RegisterOperation(asciiToHex)
	RegisterOperation(hexToASCII)
}
