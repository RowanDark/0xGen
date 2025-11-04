# Plugin Sandboxing

0xGen implements a **multi-layer plugin security model** to isolate untrusted code from the host system and other plugins. This document describes the sandboxing architecture, platform-specific implementations, and current limitations.

---

## Overview

Plugin sandboxing in 0xGen provides defense-in-depth through five independent security layers:

1. **Filesystem Isolation**: Restrict plugin file system access
2. **Resource Limits**: Prevent CPU/memory exhaustion
3. **Integrity Verification**: Hash and signature validation
4. **Capability-Based Access Control**: Fine-grained permission management
5. **Process Supervision**: Monitoring and termination tracking

**Philosophy**: Assume all plugins are potentially malicious. Minimize blast radius of compromised plugins.

---

## Layer 1: Filesystem Isolation

### Unix/Linux/macOS Implementation

**File**: `internal/plugins/runner/sandbox_unix.go`

**Mechanism**: **chroot jail** with minimal file system

```go
const (
    sandboxUserID  = 65534  // nobody user
    sandboxGroupID = 65534  // nobody group
)

func createSandboxCommand(ctx context.Context, cfg Config) (*exec.Cmd, sandboxEnv, func(), error) {
    // Creates temporary sandbox root: ~/tmp/0xgen-sandbox-*

    // Directory structure:
    //   /bin         - plugin executable only
    //   /home/plugin - isolated home directory
    //   /workspace   - working directory
    //   /tmp         - temporary directory

    cmd.SysProcAttr = &syscall.SysProcAttr{
        Chroot:  root,        // Filesystem isolation via chroot
        Setpgid: true,        // Process group isolation
    }

    // Restricted environment variables
    env = sandboxEnv{
        Path: "/bin",
        Home: "/home/plugin",
        Tmp:  "/tmp",
    }
}
```

**Security Properties**:
- ✅ Plugin cannot access host filesystem outside chroot
- ✅ Cannot modify system binaries
- ✅ Cannot read sensitive files (`/etc/passwd`, `/etc/shadow`)
- ✅ Limited to 4 directories (bin, home, workspace, tmp)
- ✅ Runs as unprivileged user (`nobody:nobody`)

**Limitations**:
- Requires root/sudo for initial chroot setup (handled by 0xgend)
- Ephemeral sandboxes cleaned up after execution

---

### Windows Implementation

**File**: `internal/plugins/runner/sandbox_windows.go`

**Mechanism**: **Isolated temporary directory with process termination**

```go
func createSandboxCommand(ctx context.Context, cfg Config) (*exec.Cmd, sandboxEnv, func(), error) {
    // Creates isolated temporary directory
    tmpDir, _ := os.MkdirTemp("", "0xgen-plugin-")

    // Sets plugin working directory to isolated temp
    cmd.Dir = tmpDir

    // Controls environment variables
    cmd.Env = []string{
        "PATH=" + tmpPath,
        "HOME=" + tmpDir,
        "TEMP=" + tmpDir,
        "TMP=" + tmpDir,
    }
}
```

**Security Properties**:
- ✅ Plugin working directory isolated to temp folder
- ✅ Environment variables restricted
- ✅ Cleanup on exit
- ⚠️ **No chroot equivalent** (Windows limitation)

**Platform Limitation**:

Windows does not provide a direct `chroot` equivalent. While Windows has container technologies (Windows Containers, App Containers), these require:

- Windows Server or Windows 10 Pro/Enterprise
- Hyper-V or process isolation mode
- Significant overhead (container startup time)
- Complex permission model

**Current Approach**: 0xGen uses process-level isolation with:
- Isolated temporary directory
- Restricted environment variables
- Process group termination
- Combined with Layers 2-5 for defense-in-depth

**Future Enhancement** (Phase 3 Roadmap):

See [`ROADMAP_COMPETITIVE.md` Phase 7](../../../ROADMAP_COMPETITIVE.md#71-windows-sandbox-enhancement) for planned improvements:

- Windows Sandbox API integration (Windows 10 1903+)
- Windows Containers (Docker Desktop requirement)
- AppContainer isolation (Windows 8+)

**Risk Mitigation**:

Even without chroot-like isolation, Windows plugin sandboxing is still robust due to:

1. **Hash Allowlisting** (Layer 3): Prevents modified binaries
2. **Signature Verification** (Layer 3): Ensures authentic plugins
3. **Capability Tokens** (Layer 4): Limits plugin permissions
4. **Process Supervision** (Layer 5): Monitors and terminates misbehaving plugins
5. **Resource Limits** (Layer 2): Prevents DoS via resource exhaustion

**Recommendation**: For maximum security on Windows, run 0xGen in WSL2 (Windows Subsystem for Linux) to leverage full chroot sandboxing.

---

## Layer 2: Resource Limits

### Unix/Linux/macOS Implementation

**File**: `internal/plugins/runner/limits_unix.go`

**Mechanism**: **POSIX RLIMIT** for hard resource constraints

```go
func startWithLimits(cmd *exec.Cmd, lim Limits) error {
    if lim.CPUSeconds > 0 {
        // CPU time limit
        newLimit := syscall.Rlimit{Cur: lim.CPUSeconds, Max: lim.CPUSeconds}
        syscall.Setrlimit(syscall.RLIMIT_CPU, &newLimit)
    }

    if lim.MemoryBytes > 0 {
        // Virtual memory limit
        newLimit := syscall.Rlimit{Cur: lim.MemoryBytes, Max: lim.MemoryBytes}
        syscall.Setrlimit(syscall.RLIMIT_AS, &newLimit)
    }
}
```

**Limits Enforced**:
- ⏱️ **CPU Time**: Maximum CPU seconds (e.g., 60s)
- 💾 **Memory**: Virtual memory limit (e.g., 512MB)
- ⏲️ **Wall Time**: Real-time execution timeout (e.g., 5 minutes)

**Enforcement**: Kernel-level hard limits. Plugin process killed if exceeded.

---

### Windows Implementation

**File**: `internal/plugins/runner/limits_windows.go`

**Mechanism**: **Process group termination with monitoring**

Windows does not support POSIX RLIMIT. Instead, 0xGen:

1. Monitors plugin process CPU and memory usage via Windows API
2. Terminates process group if limits exceeded
3. Records termination reason for auditing

**Trade-off**: Soft limits (monitoring + termination) vs. hard limits (kernel enforcement)

**Recommendation**: Set conservative limits on Windows to ensure timely termination.

---

## Layer 3: Integrity Verification

### Two-Phase Verification

**Phase 1: Hash Allowlisting**

**File**: `internal/plugins/integrity/allowlist.go`

```go
// ALLOWLIST file format: SHA-256 HASH  path/to/artifact
type Allowlist struct {
    baseDir string
    entries map[string]string  // Maps artifact path to SHA-256 hash
}

func (a *Allowlist) Verify(artifactPath string) error {
    expected, ok := a.entries[key]
    actual, err := hashFile(abs)
    if !strings.EqualFold(actual, expected) {
        return fmt.Errorf("artifact %s hash mismatch", key)
    }
}
```

**Central Allowlist**: `plugins/ALLOWLIST`

**Security Property**: Only plugins with pre-approved SHA-256 hashes can execute.

---

**Phase 2: ECDSA Signature Verification**

**File**: `internal/plugins/integrity/signature.go`

```go
func VerifySignature(artifactPath, manifestDir, repoRoot string, sig *plugins.Signature) error {
    // Detached signature validation
    // Uses public key or certificate
    // ECDSA secp256r1/P-256 curve

    if !ecdsa.VerifyASN1(publicKey, digest, signature) {
        return errors.New("signature verification failed")
    }
}
```

**Signature Format**: Base64-encoded detached ECDSA signatures (cosign-compatible)

**Public Key**: `plugins/keys/0xgen-plugin.pub`

**Security Property**: Ensures plugin authenticity and integrity. Prevents supply chain attacks.

---

## Layer 4: Capability-Based Access Control

**File**: `internal/plugins/capabilities/manager.go`

### Capability System

**10 Capability Types**:

| Capability | Permission Granted |
|------------|-------------------|
| `CAP_EMIT_FINDINGS` | Report security findings |
| `CAP_AI_ANALYSIS` | Access AI analysis surface |
| `CAP_HTTP_ACTIVE` | Make outbound HTTP requests |
| `CAP_HTTP_PASSIVE` | Observe HTTP traffic |
| `CAP_FLOW_INSPECT` | Inspect captured flows |
| `CAP_FLOW_INSPECT_RAW` | Access raw flow data |
| `CAP_WS` | WebSocket support |
| `CAP_SPIDER` | Web crawling |
| `CAP_REPORT` | Generate reports |
| `CAP_STORAGE` | File system access |

### Token-Based Authorization

```go
func (m *Manager) Issue(plugin string, capabilities []string) (token string, expires time.Time, err error) {
    // Creates base64-encoded token with:
    // - Plugin name
    // - Authorized capabilities
    // - Expiration timestamp (default: 1 minute TTL)
}

func (m *Manager) Validate(token string, plugin string) ([]string, error) {
    // Validates token before granting access
    // Checks expiration, plugin identity, capabilities
}
```

**Security Properties**:
- ✅ Short-lived tokens (1-minute TTL by default)
- ✅ Principle of least privilege
- ✅ Revocable on-demand
- ✅ Auditable (all capability grants logged)

**Manifest Declaration**:

**File**: `plugins/hydra/manifest.json`

```json
{
  "name": "hydra",
  "capabilities": [
    "CAP_EMIT_FINDINGS",
    "CAP_HTTP_PASSIVE",
    "CAP_FLOW_INSPECT",
    "CAP_AI_ANALYSIS"
  ]
}
```

**Risk Assessment**: Each capability has documented risks and mitigations in `internal/plugins/wizard/wizard.go:139-150`.

---

## Layer 5: Process Supervision

**File**: `internal/plugins/runner/supervisor.go`

### Termination Tracking

```go
type TerminationReason string

const (
    TerminationReasonTimeout     TerminationReason = "timeout"
    TerminationReasonMemoryLimit TerminationReason = "memory_limit"
    TerminationReasonCPULimit    TerminationReason = "cpu_limit"
    TerminationReasonKilled      TerminationReason = "killed"
)
```

### Structured Findings

**Finding Type**: `oxg.supervisor.termination`

**Metadata Included**:
- Task ID
- Memory limit / memory usage
- CPU limit / CPU usage
- Wall time limit / actual time
- Termination reason

**Purpose**: Audit plugin misbehavior, detect resource abuse, support incident response.

---

## Security Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ Host System                                                 │
│                                                             │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ 0xgend (Daemon)                                         │ │
│ │ - Runs as privileged user (for chroot setup)           │ │
│ │ - Manages plugin lifecycle                             │ │
│ └───────────────────────┬─────────────────────────────────┘ │
│                         │                                   │
│                         ▼                                   │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Plugin Supervisor                                       │ │
│ │ - Integrity verification (hash + signature)            │ │
│ │ - Capability token issuance                            │ │
│ │ - Resource monitoring                                   │ │
│ └───────────────────────┬─────────────────────────────────┘ │
│                         │                                   │
│                         ▼                                   │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Sandboxed Plugin Process                                │ │
│ │                                                         │ │
│ │ Unix:                   Windows:                        │ │
│ │ ┌───────────────┐      ┌───────────────┐              │ │
│ │ │ chroot jail   │      │ Temp dir      │              │ │
│ │ │ /bin          │      │ isolation     │              │ │
│ │ │ /home/plugin  │      │ C:\Temp\...   │              │ │
│ │ │ /workspace    │      │               │              │ │
│ │ │ /tmp          │      │               │              │ │
│ │ └───────────────┘      └───────────────┘              │ │
│ │                                                         │ │
│ │ RLIMIT:                Process Monitor:                │ │
│ │ - CPU: 60s             - CPU usage tracking            │ │
│ │ - Memory: 512MB        - Memory monitoring             │ │
│ │ - Wall: 5min           - Termination on limit          │ │
│ │                                                         │ │
│ │ Capabilities: CAP_AI_ANALYSIS, CAP_EMIT_FINDINGS       │ │
│ │ Token Expiry: 1 minute                                 │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Testing Sandboxing

### Manual Testing

**Test Filesystem Isolation** (Unix):

```bash
# Create malicious plugin that tries to access /etc/passwd
cat > bad-plugin.go <<'EOF'
package main
import ("fmt"; "os")
func main() {
    data, _ := os.ReadFile("/etc/passwd")
    fmt.Println(string(data))
}
EOF

go build -o bad-plugin bad-plugin.go

# Run through 0xGen sandbox (should fail to read /etc/passwd)
0xgenctl plugin run bad-plugin
```

**Test Resource Limits** (Unix):

```bash
# Create CPU-intensive plugin
cat > cpu-bomb.go <<'EOF'
package main
func main() {
    for { /* infinite loop */ }
}
EOF

go build -o cpu-bomb cpu-bomb.go

# Run with 5-second CPU limit (should terminate at 5s)
0xgenctl plugin run --cpu-limit 5 cpu-bomb
```

### Automated Testing

**Test Suite**: `internal/plugins/runner/runner_test.go`

Tests cover:
- Sandbox creation and cleanup
- Resource limit enforcement
- Termination reason tracking
- Capability validation
- Integrity verification

---

## Comparison with Competitors

| Feature | 0xGen | Burp Suite | Caido |
|---------|-------|------------|-------|
| **Filesystem Isolation** | ✅ chroot (Unix), temp dir (Windows) | ❌ JVM only | ❌ None |
| **Resource Limits** | ✅ RLIMIT (Unix), monitor (Windows) | ❌ | ❌ |
| **Plugin Signing** | ✅ ECDSA | ❌ | ❌ |
| **Hash Allowlisting** | ✅ SHA-256 | ❌ | ❌ |
| **Capability Tokens** | ✅ 1-min TTL | ❌ | ❌ |
| **Termination Tracking** | ✅ Structured findings | ❌ | ❌ |

**0xGen has the strongest plugin security model in the industry.**

---

## Security Recommendations

### For Operators

1. **Keep Allowlist Updated**: Regularly update `plugins/ALLOWLIST` with trusted plugin hashes
2. **Review Capabilities**: Only grant necessary capabilities to plugins
3. **Monitor Terminations**: Check `oxg.supervisor.termination` findings for abuse
4. **Use WSL2 on Windows**: For maximum security, run 0xGen in WSL2 to leverage chroot
5. **Set Conservative Limits**: Start with low resource limits, increase as needed

### For Plugin Developers

1. **Request Minimal Capabilities**: Only declare needed capabilities in manifest
2. **Document Resource Usage**: Specify expected CPU/memory requirements
3. **Sign Your Plugins**: Use `0xgenctl plugin sign` to create ECDSA signatures
4. **Test in Sandbox**: Verify plugin works under resource constraints
5. **Follow Security Guidelines**: See [`PLUGIN_GUIDE.md`](../../../PLUGIN_GUIDE.md)

---

## Future Enhancements

### Phase 3 Roadmap (Q1 2025)

See [`ROADMAP_COMPETITIVE.md`](../../../ROADMAP_COMPETITIVE.md) for:

- **Windows Sandbox API Integration**: Use Windows 10 Sandbox API for better isolation
- **Container-Based Sandboxing**: Docker/Podman integration for portable isolation
- **seccomp-bpf Filters**: Linux syscall filtering for additional protection
- **Network Namespace Isolation**: Per-plugin network namespaces

### Phase 7 Roadmap (Q3-Q4 2026)

- **Kubernetes Integration**: Run plugins in isolated pods
- **Distributed Sandboxing**: Remote plugin execution in dedicated VMs
- **Hardware-Assisted Isolation**: Intel SGX, AMD SEV for confidential computing

---

## Related Documentation

- [Threat Model](threat-model.md) - Overall security architecture
- [Supply Chain Security](supply-chain.md) - SLSA, SBOM, signing
- [Plugin Development Guide](../plugins/sdk-tutorial.md) - Building secure plugins
- [Roadmap](../../../ROADMAP_COMPETITIVE.md) - Future security enhancements

---

## Security Contact

Found a sandbox escape or security issue? Please report responsibly:

- Email: security@0xgen.io
- Bug Bounty: Coming soon (Phase 5)
- Disclosure Policy: See [`SECURITY.md`](../../../SECURITY.md)

---

**Last Updated**: 2025-11-03
**Version**: Phase 2 (Alpha)
