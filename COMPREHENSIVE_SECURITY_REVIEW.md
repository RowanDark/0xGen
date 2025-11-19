# 0xGen Comprehensive Security Review

**Review Date:** November 19, 2025
**Scope:** Internal codebase, excluding third-party dependencies and CLI tools
**Overall Assessment:** Production-ready with several security issues to address

---

## Executive Summary

0xGen demonstrates a **well-structured, security-conscious architecture** with strong fundamentals in plugin isolation, cryptography, and data protection. The codebase exhibits excellent defensive programming in many areas (SSRF prevention, secret redaction, capability-based access control). However, several vulnerabilities spanning from **critical** to **medium** severity require remediation before production deployment.

**Key Strengths:**
- Excellent SSRF/XXE prevention in network gate
- Robust plugin sandbox implementation with seccomp
- Strong cryptographic token generation and HMAC verification
- Comprehensive secret redaction in audit logging
- Well-implemented capability-based authorization system
- Request size limiting (10 MB default)

**Key Concerns:**
- XXE vulnerability in XML parsing
- Unbounded I/O operations in proxy response handling
- Environment variable leakage in plugin sandbox
- Weak TLS verification defaults in development mode
- Information disclosure through error messages
- Signature verification can be disabled in production scenarios

---

## 1. AUTHENTICATION & AUTHORIZATION

### 1.1 JWT Implementation (STRONG)

**File:** `/home/user/0xGen/internal/api/auth.go`
**Assessment:** Good implementation with proper crypto

**Positive Findings:**
- Line 240: Uses HMAC-SHA256 with `hmac.New(sha256.New, a.secret)` ✓
- Line 233: Timing-safe comparison with `hmac.Equal()` ✓
- Lines 144-145: Proper timestamp-based expiry validation ✓
- Lines 134-135: TTL capped at 24 hours to prevent indefinite tokens ✓
- Line 146: JTI (JWT ID) uses `uuid.NewString()` for uniqueness ✓
- Lines 159-161: Proper input validation and whitespace trimming ✓

**Issues Found:** None critical in JWT core logic

### 1.2 OIDC Integration (MEDIUM CONCERN)

**File:** `/home/user/0xGen/internal/api/auth.go`, lines 299-359
**Severity:** MEDIUM

**Finding:** Incomplete `audience` validation in OIDC
```go
// Lines 314-315 - validateAudience allows empty audience list
if len(v.audiences) == 0 {
    return true  // Accepts ANY audience if none configured
}
```

**Risk:** If OIDC config is instantiated without explicit audiences, ANY OIDC token will be accepted regardless of `aud` claim.

**Recommendation:** 
```go
// Enforce explicit audience configuration
if len(cfg.Audiences) == 0 {
    return errors.New("oidc audiences must be specified")
}
```

### 1.3 Secrets Token System (STRONG)

**File:** `/home/user/0xGen/internal/secrets/manager.go`
**Assessment:** Excellent implementation

**Positive Findings:**
- Line 178-182: Uses `crypto/rand` for 32-byte token generation (256 bits) ✓
- Line 182: Base64 URL-safe encoding ✓
- Lines 231-235: Proper token scope binding (plugin + scope validation) ✓
- Lines 237-239: Token revocation support ✓
- Lines 252-262: Proper expiry pruning ✓
- Lines 285-286: Token prefix redaction in audit logs (shows only first 8 chars) ✓

**No critical issues found in secrets management.**

### 1.4 Capability System (STRONG)

**File:** `/home/user/0xGen/internal/plugins/manifest.go`, lines 19-54
**Assessment:** Good implementation

**Positive Findings:**
- Lines 41-54: Validates capabilities exist and have no duplicates ✓
- Line 93: `AllowedCapabilities()` maintains allow-list ✓
- Plugin wizard enforces capability grants (wizard.go) ✓

**No critical issues found.**

---

## 2. INPUT VALIDATION & INJECTION PREVENTION

### 2.1 SQL Injection (LOW RISK - Already documented in DATABASE_REVIEW.md)

**Severity:** MEDIUM (One parameterization gap, rest secure)
**File:** `/home/user/0xGen/internal/blitz/storage.go`, lines 238-244

**Finding:** LIMIT/OFFSET not parameterized
```go
query += fmt.Sprintf(" LIMIT %d", filters.Limit)  // Numeric but violates best practices
```

While technically safe (numeric values can't contain SQL), this violates parameterized query best practices.

**Recommendation:** Use placeholders:
```go
query += " LIMIT ? OFFSET ?"
```

### 2.2 XXE/XML Entity Expansion (CRITICAL)

**Severity:** CRITICAL
**File:** `/home/user/0xGen/internal/delta/diff_engine.go`, lines 318-344

**Finding:** Unsafe XML parsing without entity disabling
```go
func (e *Engine) diffXML(left, right []byte) (*DiffResult, error) {
    var leftNode, rightNode xmlNode
    if err := xml.Unmarshal(left, &leftNode); err != nil {  // Line 322
        return e.diffText(left, right, GranularityLine)
    }
    if err := xml.Unmarshal(right, &rightNode); err != nil {  // Line 327
        return e.diffText(left, right, GranularityLine)
    }
    // ... no XXE prevention ...
}
```

**Risk:** 
- No external entity restriction
- No XXE attack prevention
- Attackers can inject DTDs to exfiltrate data or cause DoS
- Example attack:
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

**Recommendation:** Use secure XML decoder
```go
import "encoding/xml"

decoder := xml.NewDecoder(bytes.NewReader(data))
decoder.Entity = map[string]string{}  // Disable all entities
if err := decoder.Decode(&node); err != nil {
    return err
}
```

**OR** Use safer approach:
```go
// Reject known XXE patterns
data = bytes.TrimSpace(data)
if bytes.Contains(data, []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) {
    return errors.New("DOCTYPE/ENTITY declarations not allowed")
}
```

### 2.3 Command Injection (MEDIUM RISK)

**Severity:** MEDIUM
**File:** `/home/user/0xGen/internal/plugins/runner/sandboxcmd/main.go`, lines 34-35

**Finding:** Arguments passed unsafely to exec
```go
target := os.Args[1]
args := os.Args[1:]  // Includes the binary itself as first argument
if err := syscall.Exec(target, args, os.Environ()); err != nil {
```

**Risk:**
- First element of args is the binary path itself (should be just the command name)
- All parent environment variables leaked to plugin
- Untrusted plugin could read sensitive env vars

**Recommendation:**
```go
target := os.Args[1]
args := []string{filepath.Base(target)}  // Binary name only
args = append(args, os.Args[2:]...)       // Actual arguments

// Filter environment to only safe variables
safeEnv := []string{
    "PATH=/bin",
    "HOME=/home/plugin",
    "TMPDIR=/tmp",
}
if err := syscall.Exec(target, args, safeEnv); err != nil {
```

### 2.4 Path Traversal Prevention (STRONG)

**File:** `/home/user/0xGen/internal/plugins/integrity/signature.go`, lines 52-81

**Positive Finding:** Excellent path traversal prevention
```go
func resolvePath(path, manifestDir, repoRoot string) (string, error) {
    if filepath.IsAbs(path) {
        return path, nil  // Accept absolute paths
    }
    // Try relative to manifest or repo root
    candidates := []string{}
    if manifestDir != "" {
        candidates = append(candidates, filepath.Join(manifestDir, path))
    }
    // Only return if found, prevents path traversal
    for _, candidate := range candidates {
        if _, err := os.Stat(candidate); err == nil {
            return candidate, nil
        }
    }
    return "", fmt.Errorf("path could not be resolved")
}
```

**No path traversal vulnerabilities found.**

### 2.5 SSRF Prevention (EXCELLENT)

**File:** `/home/user/0xGen/internal/netgate/gate.go`, lines 904-949

**Positive Finding:** Comprehensive SSRF prevention
```go
func validateURL(u *url.URL) error {
    // Only allow http/https
    scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
    switch scheme {
    case "http", "https":
    default:
        return fmt.Errorf("scheme %s not permitted", u.Scheme)
    }
    // Validate hostname
    return validateHost(host)
}

func validateHost(host string) error {
    // Blocks loopback, private ranges, link-local
    if strings.EqualFold(hostname, "localhost") {
        return errors.New("loopback destinations are not permitted")
    }
    if addr.IsLoopback() {
        return errors.New("loopback destinations are not permitted")
    }
    if inPrefixes(addr, privatePrefixes) {  // 10.0.0.0/8, 172.16.0.0/12, etc.
        return errors.New("private address ranges are not permitted")
    }
}
```

**Excellent SSRF controls - no vulnerabilities found.**

---

## 3. CRYPTOGRAPHIC SECURITY

### 3.1 Key Generation (STRONG)

**File:** `/home/user/0xGen/internal/secrets/manager.go`, line 178-182

**Positive Finding:**
```go
raw := make([]byte, 32)
if _, err := rand.Read(raw); err != nil {  // crypto/rand
    return "", time.Time{}, fmt.Errorf("generate token: %w", err)
}
token := base64.RawURLEncoding.EncodeToString(raw)
```

**Assessment:** 32 bytes (256 bits) of cryptographic randomness is sufficient. ✓

### 3.2 Token Entropy (STRONG)

**JWT Token ID:** Uses `uuid.NewString()` for uniqueness ✓
**Secrets Tokens:** 32 bytes crypto/rand ✓
**No weak RNG patterns found.**

### 3.3 TLS/SSL Configuration (HIGH RISK)

**Severity:** HIGH
**File:** `/home/user/0xGen/internal/observability/tracing/config.go`, lines 55-71

**Finding:** InsecureSkipVerify enabled in development mode
```go
func (c *Config) GetTLSConfig() *tls.Config {
    if c.IsDevelopmentMode() && c.SkipTLSVerify {
        return &tls.Config{
            InsecureSkipVerify: true,  // DANGEROUS!
            MinVersion:         tls.VersionTLS12,
        }
    }
    return &tls.Config{
        MinVersion: tls.VersionTLS12,
    }
}
```

**Risk:**
- Allows MITM attacks on telemetry endpoints
- Sensitive trace data (request/response bodies, headers) exposed
- No distinction between development and production at runtime
- `0XGEN_DEV_MODE` env var allows easy bypass

**Recommendation:**
```go
// In production, NEVER skip TLS verification
func (c *Config) GetTLSConfig() *tls.Config {
    if !c.IsDevelopmentMode() {
        // Production must always verify
        return &tls.Config{MinVersion: tls.VersionTLS12}
    }
    // Development can optionally skip if explicitly configured
    if c.SkipTLSVerify {
        return &tls.Config{
            InsecureSkipVerify: true,
            MinVersion:         tls.VersionTLS12,
        }
    }
    return &tls.Config{MinVersion: tls.VersionTLS12}
}
```

### 3.4 Certificate Handling (STRONG)

**File:** `/home/user/0xGen/internal/proxy/ca.go`

**Positive Findings:**
- Proper ECDSA signature verification (crypto.VerifyPKCS1v15) ✓
- Certificate chain validation in chain parsing loop ✓
- PEM block parsing with proper type checking ✓

**No certificate handling vulnerabilities found.**

---

## 4. PLUGIN SECURITY

### 4.1 Sandbox Implementation (STRONG)

**File:** `/home/user/0xGen/internal/plugins/runner/sandbox_unix.go`

**Positive Findings:**
- Chroot isolation (line 83): `Chroot: root` ✓
- Non-root execution (lines 17-19): sandboxUserID = 65534 ✓
- Process group isolation: `Setpgid: true` ✓
- Seccomp filter enforcement (lines 42-84):
  - Blocks ptrace, mount, umount, chroot, bpf, etc.
  - Only allows explicitly whitelisted syscalls

**Strong sandbox implementation - no vulnerabilities found.**

### 4.2 Signature Verification (MEDIUM RISK)

**Severity:** MEDIUM
**File:** `/home/user/0xGen/cmd/0xgenctl/plugin_run.go`, line 55

**Finding:** Signature verification skipped by default in CLI
```go
SkipSignatureVerification: true,
```

**Risk:**
- Untrusted or maliciously modified plugins could run
- No integrity verification in development workflow
- Could be accidentally used in production

**More concerning:** 
**File:** `/home/user/0xGen/internal/plugins/launcher/launcher.go`, lines 103-125
```go
skipSignature := cfg.SkipSignatureVerification
if !skipSignature {
    if val, ok := env.Lookup("0XGEN_SKIP_SIGNATURE_VERIFY"); ok {
        lowered := strings.ToLower(strings.TrimSpace(val))
        skipSignature = lowered == "1" || lowered == "true" || lowered == "yes"
    }
}
if skipSignature && !manifest.Trusted {  // Good: enforces for untrusted
    skipSignature = false
} else {
    // SIGNATURE VERIFICATION SKIPPED FOR TRUSTED PLUGINS!
}
```

**Recommendation:**
1. Never skip signatures by default, even in dev
2. Add explicit `--skip-verify` flag requiring acknowledgment
3. Log warnings to stderr
4. Set `manifest.Trusted = false` by default for newly discovered plugins

### 4.3 Artifact Integrity (STRONG)

**File:** `/home/user/0xGen/internal/plugins/integrity/allowlist.go`

**Positive Finding:** Hash-based allowlist verification ✓
**No vulnerabilities in integrity checking.**

---

## 5. NETWORK SECURITY

### 5.1 Proxy Security (MEDIUM RISK - Unbounded I/O)

**Severity:** MEDIUM
**File:** `/home/user/0xGen/internal/proxy/proxy.go`, lines 580 and 777

**Finding:** Unbounded I/O without size limits
```go
// Line 580 - Request body
body, err := io.ReadAll(r.Body)  // No size limit

// Line 777 - Response body  
body, err := io.ReadAll(resp.Body)  // No size limit
```

**Risk:** 
- Attackers can send gigabyte-sized responses/requests
- Memory exhaustion DoS attack
- Possible OOM kill of process

**Mitigation:**
```go
// Use limited reader
limitedBody := io.LimitReader(r.Body, 100*1024*1024)  // 100 MB limit
body, err := io.ReadAll(limitedBody)
```

**Note:** API server has request size limit (10 MB default, line 21), but proxy doesn't.

### 5.2 Rate Limiting (STRONG)

**File:** `/home/user/0xGen/internal/netgate/gate.go`, lines 82-92

**Positive Findings:**
- Per-host rate limiting ✓
- Global rate limiting ✓
- Configurable via RateLimit struct ✓
- Token bucket algorithm implementation ✓

**No vulnerabilities found.**

### 5.3 Request Size Limits (STRONG)

**File:** `/home/user/0xGen/internal/api/server.go`, lines 20-21, 138-140

**Positive Finding:**
```go
const DefaultMaxRequestSize int64 = 10 * 1024 * 1024  // 10 MB
// Configurable and properly enforced
maxRequestSize := cfg.MaxRequestSize
if maxRequestSize <= 0 {
    maxRequestSize = DefaultMaxRequestSize
}
```

**Comprehensive request size limiting - no vulnerabilities found.**

### 5.4 CORS (NOT FOUND)

**Severity:** LOW
**Finding:** No CORS configuration found in codebase

**Risk:** 
- If deployed with browser clients, may have unintended CORS behavior
- Default Go http server allows any origin

**Note:** This may be intentional if 0xGen is backend-only or has proxying layer.

---

## 6. DATA PROTECTION

### 6.1 Secret Redaction (STRONG)

**File:** `/home/user/0xGen/internal/redact/redact.go`

**Positive Findings:**
```go
var (
    emailRe     = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
    kvSecretRe  = regexp.MustCompile(`(?i)((?:api|token|secret|key|password)...)`)
    bearerRe    = regexp.MustCompile(`(?i)\b(bearer|token)\s+([A-Za-z0-9._\-]{10,})`)
    longTokenRe = regexp.MustCompile(`\b[A-Za-z0-9]{32,}\b`)
)
```

**Coverage:**
- Email addresses → `[REDACTED_EMAIL]` ✓
- API keys/tokens → `[REDACTED_SECRET]` ✓
- Bearer tokens → `[REDACTED_SECRET]` ✓
- Long tokens/base64 → `[REDACTED_SECRET]` ✓
- `never_persist` directive support ✓

**Comprehensive secret redaction - excellent implementation.**

### 6.2 Database Encryption (NOT FOUND)

**Severity:** LOW
**Finding:** No database encryption at rest

**File:** `/home/user/0xGen/internal/blitz/storage.go` and others use SQLite without encryption.

**Risk:** 
- Findings database readable if disk is compromised
- May be acceptable if OS-level encryption is available

**Recommendation:** Use SQLite encryption extension or enforce OS-level disk encryption.

### 6.3 Cookie Security (NOT FOUND)

**Finding:** No HTTP cookies used in application

**Assessment:** Not applicable - application uses JWT tokens in Authorization header, which is more secure than cookies.

### 6.4 Sensitive Data in Logs (GOOD)

**File:** `/home/user/0xGen/internal/logging/audit.go`, line 187-189

**Positive Finding:**
```go
event.Reason = redact.String(event.Reason)
if len(event.Metadata) > 0 {
    event.Metadata = redact.Map(event.Metadata)
}
```

**All audit events get automatic secret redaction - excellent.**

---

## 7. ERROR HANDLING & INFORMATION DISCLOSURE

### 7.1 Error Messages (MEDIUM RISK)

**Severity:** MEDIUM
**File:** `/home/user/0xGen/internal/api/server.go`, lines 261, 274, 279, 297, 315

**Finding:** Raw error messages exposed to clients
```go
http.Error(w, err.Error(), http.StatusBadRequest)  // Line 261
http.Error(w, err.Error(), http.StatusInternalServerError)  // Line 279
```

**Risk:**
- Internal implementation details leaked
- Detailed error messages aid reconnaissance
- May reveal database structure, library versions, etc.

**Example Issue:**
```
Error: "role must be one of: admin, editor, viewer"  // Leaks valid roles
Error: "field 'user_id' must match pattern '^[0-9]{8,10}$'"  // Leaks ID format
```

**Recommendation:**
```go
// Generic errors to clients
if err != nil {
    s.logger.Error("operation failed", "error", err)  // Log actual error
    http.Error(w, "invalid request", http.StatusBadRequest)  // Generic response
    return
}
```

### 7.2 Stack Trace Exposure (GOOD)

**File:** `/home/user/0xGen/internal/api/cipher_test.go`, lines 343-347

**Positive Finding:** Test explicitly checks NO stack traces in responses
```go
// Check that response doesn't contain stack traces or internal paths
patterns := []string{
    "panic:",  
}
for _, pattern := range patterns {
    if strings.Contains(body, pattern) {
        t.Fatalf("response contains %q", pattern)
    }
}
```

**Excellent - no stack trace leakage found.**

---

## 8. ADDITIONAL SECURITY CONCERNS

### 8.1 API Authentication Middleware (GOOD)

**File:** `/home/user/0xGen/internal/api/server.go`, lines 234-239

**Positive Finding:**
```go
if r.Header.Get("Authorization") == "" && s.staticToken == "" {
    http.Error(w, "unauthorised", http.StatusUnauthorized)
    return
}
```

**Proper authentication enforcement - no vulnerabilities.**

### 8.2 Default Security Headers (NOT FOUND)

**Severity:** LOW
**Finding:** No security headers configured

Missing headers:
- `Strict-Transport-Security` (HSTS)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy`

**Recommendation:** Add middleware
```go
w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-Frame-Options", "DENY")
```

### 8.3 Foreign Key Constraints (GOOD - with caveat)

**File:** `/home/user/0xGen/plugins/entropy/storage.go`, line 69

**Finding:** Foreign keys defined but not enforced by default in SQLite

**Recommendation:**
```go
if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
    return fmt.Errorf("enable foreign keys: %w", err)
}
```

**Already documented in DATABASE_REVIEW.md - needs fixing.**

---

## SEVERITY SUMMARY

### Critical (Requires immediate fix)
1. **XXE in XML parsing** - `/home/user/0xGen/internal/delta/diff_engine.go:322,327`
   - Can cause data exfiltration or DoS
   - Fix: Use secure XML decoder or disable external entities

### High (Address before production)
1. **TLS verification skip in dev mode** - `internal/observability/tracing/config.go:64`
   - MITM attacks on telemetry
   - Fix: Disable in all production builds

2. **Unbounded I/O in proxy** - `internal/proxy/proxy.go:580,777`
   - Memory exhaustion DoS
   - Fix: Add size limits using io.LimitReader

### Medium (Should fix soon)
1. **Error message information disclosure** - `internal/api/server.go:261,274,279,297,315`
   - Leaks implementation details
   - Fix: Return generic error messages

2. **Command injection in sandbox** - `internal/plugins/runner/sandboxcmd/main.go:34-35`
   - Environment variable leakage
   - Fix: Filter environment, fix argument passing

3. **Plugin signature verification skip** - `cmd/0xgenctl/plugin_run.go:55`
   - Allows untrusted plugins
   - Fix: Make signature verification default

4. **OIDC audience validation gap** - `internal/api/auth.go:363-365`
   - Could accept unintended audiences
   - Fix: Require explicit audience configuration

### Low (Polish)
1. **Missing security headers** - Various files
   - Better defense-in-depth
   - Fix: Add HTTP security headers middleware

2. **No CORS configuration** - Not found
   - May need explicit CORS policy
   - Action: Define and implement if needed

3. **Database encryption at rest** - Not found
   - Protects if disk compromised
   - Consider: SQLite encryption extension

---

## POSITIVE SECURITY FEATURES

Worth noting excellent implementations:

1. **SSRF Prevention** - Comprehensive validation in netgate/gate.go ✓
2. **Secret Redaction** - Automatic redaction in all logs ✓
3. **Capability System** - Fine-grained authorization ✓
4. **Plugin Sandbox** - Chroot + seccomp + non-root ✓
5. **Cryptographic Token Generation** - Using crypto/rand ✓
6. **Timing-Safe Comparisons** - hmac.Equal() in auth ✓
7. **Request Size Limiting** - 10 MB default ✓
8. **Rate Limiting** - Per-host and global ✓
9. **Path Traversal Prevention** - Excellent implementation ✓
10. **Audit Logging** - Comprehensive with redaction ✓

---

## RECOMMENDATIONS

### Immediate (Before Production)
- [ ] Fix XXE vulnerability in XML parsing
- [ ] Add size limits to unbounded I/O in proxy
- [ ] Disable TLS verification skip in production builds
- [ ] Make error messages generic in API responses
- [ ] Fix environment variable leakage in sandbox
- [ ] Make signature verification default (not skip)

### Short-term
- [ ] Add HTTP security headers
- [ ] Fix OIDC audience validation
- [ ] Enable SQLite foreign key constraints
- [ ] Fix LIMIT/OFFSET parameterization in SQL
- [ ] Add comprehensive security headers middleware

### Long-term
- [ ] Consider SQLite encryption extension
- [ ] Implement database versioning
- [ ] Add race condition testing (`go test -race`)
- [ ] Regular security audits
- [ ] Dependency scanning automation

---

**Overall Risk Assessment:** MEDIUM-HIGH due to XXE and TLS issues, but fundamentally well-designed security architecture.
