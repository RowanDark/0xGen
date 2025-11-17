// Package cipher provides encoding, decoding, and transformation operations
// for security testing and payload analysis.
//
// # Overview
//
// Cipher is 0xGen's answer to Burp Decoder, offering:
//   - AI-powered auto-detection of encodings (90%+ accuracy)
//   - Transformation chaining (pipeline multiple operations)
//   - JWT signing/validation
//   - Recipe library (save and reuse transformation chains)
//
// # Quick Start
//
// Basic encoding/decoding:
//
//	// Get an operation
//	op, _ := cipher.GetOperation("base64_encode")
//
//	// Execute it
//	result, _ := op.Execute(context.Background(), []byte("Hello, World!"), nil)
//	// result: []byte("SGVsbG8sIFdvcmxkIQ==")
//
// # Auto-Detection
//
// Automatically detect encoding:
//
//	detector := cipher.NewSmartDetector()
//	results, _ := detector.Detect(ctx, []byte("SGVsbG8gV29ybGQh"))
//
//	for _, r := range results {
//	    fmt.Printf("%s (%.0f%% confidence): %s\n",
//	        r.Encoding, r.Confidence*100, r.Reasoning)
//	}
//
// # Transformation Pipelines
//
// Chain multiple operations together:
//
//	pipeline := &cipher.Pipeline{
//	    Operations: []cipher.OperationConfig{
//	        {Name: "base64_encode"},
//	        {Name: "url_encode"},
//	    },
//	    Reversible: true,
//	}
//
//	// Execute forward
//	encoded, _ := pipeline.Execute(ctx, []byte("test"))
//
//	// Reverse the pipeline
//	reversed, _ := pipeline.Reverse()
//	decoded, _ := reversed.Execute(ctx, encoded)
//
// # Recipe Management
//
// Save and load transformation recipes:
//
//	rm := cipher.NewRecipeManager("/path/to/recipes")
//
//	recipe := &cipher.Recipe{
//	    Name:        "double-base64",
//	    Description: "Double Base64 encoding (common obfuscation)",
//	    Tags:        []string{"encoding", "obfuscation"},
//	    Pipeline: cipher.Pipeline{
//	        Operations: []cipher.OperationConfig{
//	            {Name: "base64_encode"},
//	            {Name: "base64_encode"},
//	        },
//	        Reversible: true,
//	    },
//	}
//
//	rm.SaveRecipe(recipe)
//
// # JWT Operations
//
// Working with JSON Web Tokens:
//
//	// Decode a JWT (no verification)
//	decoder, _ := cipher.GetOperation("jwt_decode")
//	decoded, _ := decoder.Execute(ctx, []byte(token), nil)
//
//	// Verify with secret
//	verifier, _ := cipher.GetOperation("jwt_verify")
//	result, _ := verifier.Execute(ctx, []byte(token), map[string]interface{}{
//	    "secret": "your-secret-key",
//	})
//
//	// Sign a JWT
//	signer, _ := cipher.GetOperation("jwt_sign")
//	claims := `{"sub":"user123","name":"Test User"}`
//	token, _ := signer.Execute(ctx, []byte(claims), map[string]interface{}{
//	    "secret": "your-secret-key",
//	})
//
// # Available Operations
//
// Encoding/Decoding:
//   - base64_encode/decode - Standard Base64
//   - base64url_encode/decode - URL-safe Base64
//   - url_encode/decode - URL encoding (percent encoding)
//   - html_encode/decode - HTML entity encoding
//   - hex_encode/decode - Hexadecimal encoding
//   - binary_encode/decode - Binary string encoding
//   - ascii_to_hex/hex_to_ascii - ASCII/Hex conversion
//
// Compression:
//   - gzip_compress/decompress - Gzip compression
//
// Hashing:
//   - md5_hash - MD5 hash (not reversible)
//   - sha1_hash - SHA-1 hash (not reversible)
//   - sha256_hash - SHA-256 hash (not reversible)
//   - sha512_hash - SHA-512 hash (not reversible)
//
// JWT:
//   - jwt_decode - Decode JWT token without verification
//   - jwt_verify - Verify JWT token with secret
//   - jwt_sign - Sign JWT token with secret
//
// # Detection Accuracy
//
// The auto-detection system achieves 90%+ accuracy on common encodings:
//   - Base64: 90-95% confidence
//   - Hexadecimal: 80-95% confidence (higher with 0x prefix)
//   - URL encoding: 50-95% confidence (based on density)
//   - JWT: 95% confidence
//   - Gzip: 99% confidence (magic bytes)
//   - HTML entities: 40-90% confidence (based on count)
//   - Binary: 60-85% confidence (8-bit aligned strings)
//
// # Thread Safety
//
// The operation registry is thread-safe and can be accessed concurrently.
// Individual operations are stateless and safe for concurrent use.
// RecipeManager uses internal locking for thread-safe recipe management.
package cipher
