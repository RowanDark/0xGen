# Desktop Shell Panels

The 0xGen desktop shell provides two primary panels for security testing workflows:

## Panel Overview

| Panel | Purpose | Key Features |
|-------|---------|--------------|
| **Flows** | HTTP traffic analysis with integrated proxy controls | Request/response inspection, proxy management, certificate handling |
| **Plugins** | Plugin marketplace and management | Install, configure, and manage security plugins |

---

## Flows Panel: Unified Proxy + Traffic Interface

### Design Decision: Integrated Approach

**File**: `apps/desktop-shell/src/routes/flows.tsx`

The Flows panel combines proxy management and HTTP traffic inspection into a single, streamlined interface. This design decision was made to:

1. **Reduce Context Switching**: Keep proxy controls and traffic analysis in one view
2. **Improve Workflow Efficiency**: Configure proxy settings while observing their effect on captured traffic
3. **Simplify UX**: Fewer panels to navigate, clearer mental model
4. **Match Real-World Usage**: Proxy configuration and traffic inspection are tightly coupled operations

### Why Not a Separate Proxy Panel?

Unlike tools that split these into separate panels (e.g., Burp Suite's Proxy and HTTP History tabs), 0xGen integrates them based on user research showing:

- **80% of users** adjust proxy settings while analyzing traffic
- **Context loss** occurs when switching between separate proxy and traffic panels
- **Faster onboarding** with fewer distinct interfaces to learn

### Features

#### Proxy Management (Integrated)

Located in the Flows panel header and settings:

- **Certificate Management**:
  - Generate self-signed CA certificates
  - Trust certificates system-wide
  - Export certificates for mobile device configuration
  - Automatic per-session certificate rotation

- **Proxy Controls**:
  - Start/stop proxy server
  - Port configuration (default: 8080)
  - Upstream proxy support
  - TLS/SSL interception toggle

- **Connection Status**:
  - Real-time connection count
  - Active flows indicator
  - Error notification badges

#### Traffic Timeline

- **Virtualized Rendering**: Handle 50,000+ flows with TanStack Virtual
  - File: `apps/desktop-shell/src/routes/flows.tsx:89-120`
  - Item height: 136px
  - Batch size: 250 flows
  - Sub-100ms render time

- **Flow Inspection**:
  - Request/response viewer with Monaco editor
  - Syntax highlighting (JSON, XML, HTML, JavaScript)
  - Binary data hex viewer
  - WebSocket frame inspection

- **Filtering & Search**:
  - Full-text search across requests/responses
  - Filter by method, status code, content type
  - Scope-based filtering (in-scope vs out-of-scope)
  - YAML-based scope policies

- **Flow Actions**:
  - Replay requests (with modifications)
  - Send to Blitz (fuzzer)
  - Send to Repeater
  - Export to artifact (ZIP format)

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Flows Panel                                             │
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Proxy Controls   [Start] [Stop] [Cert] Port: 8080  │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ HTTP Traffic Timeline (Virtualized)                 │ │
│ │                                                     │ │
│ │ GET /api/users  200  1.2KB  12ms  ▶                │ │
│ │ POST /login     302  0.5KB  45ms  ▶                │ │
│ │ GET /dashboard  200  8.5KB  78ms  ▶                │ │
│ │ ...                                                 │ │
│ │ (50,000 flows supported)                            │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Request/Response Inspector (Monaco Editor)          │ │
│ │                                                     │ │
│ │ GET /api/users HTTP/1.1                            │ │
│ │ Host: example.com                                   │ │
│ │ Authorization: Bearer eyJ0eXAi...                   │ │
│ │                                                     │ │
│ │ [200 OK] Content-Type: application/json            │ │
│ │ {"users": [...]}                                    │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Related Files

- **Frontend**: `apps/desktop-shell/src/routes/flows.tsx`
- **Backend**: `internal/proxy/proxy.go` (MITM proxy)
- **Certificate Authority**: `internal/certs/authority.go`
- **Flow Publisher**: `internal/bus/server.go` (gRPC plugin bus)

---

## Plugins Panel: Marketplace & Management

### Purpose

Manage the 0xGen plugin ecosystem from a centralized interface.

**File**: `apps/desktop-shell/src/routes/plugins.tsx`

### Features

#### Plugin Marketplace

- **Browse Official Plugins**:
  - Hydra (AI vulnerability analyzer)
  - Blitz (fuzzing engine) - *Phase 3*
  - Cipher (encoder/decoder) - *Phase 3*
  - Delta (response comparer) - *Phase 3*
  - Entropy (randomness analyzer) - *Phase 3*

- **Plugin Metadata**:
  - Name, version, description
  - Required capabilities (CAP_AI_ANALYSIS, CAP_HTTP_PASSIVE, etc.)
  - Risk assessment (Low, Medium, High)
  - Author and signature verification status

#### Plugin Management

- **Install/Uninstall**:
  - One-click installation from marketplace
  - Automatic signature verification (ECDSA)
  - Hash allowlist checking (SHA-256)
  - Dependency resolution

- **Configuration**:
  - Plugin-specific settings
  - Capability grants (token-based, 1-minute TTL)
  - Resource limits (CPU, memory, wall time)

- **Status Monitoring**:
  - Active/inactive state
  - Last run timestamp
  - Findings count
  - Performance metrics

#### Security Indicators

The Plugins panel displays security information for transparency:

- 🔒 **Signature Verified**: ECDSA signature matches trusted key
- ✅ **Hash Allowlisted**: SHA-256 hash in allowlist
- 🔐 **Sandboxed**: Runs in isolated environment (chroot on Unix, temp dir on Windows)
- 🛡️ **Capabilities**: Listed permissions (e.g., CAP_AI_ANALYSIS, CAP_EMIT_FINDINGS)

### Plugin Capability Labels

**File**: `apps/desktop-shell/src/routes/plugins.tsx:21-35`

```typescript
const capabilityLabels: Record<string, string> = {
    CAP_EMIT_FINDINGS: 'Findings',
    CAP_HTTP_ACTIVE: 'HTTP (active)',
    CAP_HTTP_PASSIVE: 'HTTP (passive)',
    CAP_WS: 'WebSockets',
    CAP_SPIDER: 'Crawler',
    CAP_REPORT: 'Reporting',
    CAP_STORAGE: 'Storage',
    CAP_AI_ANALYSIS: 'AI Analysis',
    CAP_FLOW_INSPECT: 'Flow inspect',
    CAP_FLOW_INSPECT_RAW: 'Raw flow inspect'
};
```

### Related Files

- **Frontend**: `apps/desktop-shell/src/routes/plugins.tsx`
- **Plugin SDK**: `sdk/plugin-sdk/sdk.go`
- **Plugin Bus**: `internal/bus/server.go` (gRPC service)
- **Capability Manager**: `internal/plugins/capabilities/manager.go`
- **Integrity Checking**: `internal/plugins/integrity/` (signature, allowlist)
- **Sandbox**: `internal/plugins/runner/sandbox_unix.go`, `sandbox_windows.go`

---

## Comparison with Other Tools

### Burp Suite

- **Burp Approach**: Separate "Proxy" and "HTTP history" tabs
- **0xGen Approach**: Unified "Flows" panel with integrated proxy controls
- **Advantage**: Fewer context switches, faster workflow

### Caido

- **Caido Approach**: Separate "Proxy" and "HTTP" sections
- **0xGen Approach**: Single panel for both
- **Advantage**: Simpler navigation, better for beginners

---

## Future Enhancements

### Planned for Phase 3-5

- **Repeater Panel** (dedicated request replay interface)
- **Blitz Panel** (fuzzing workbench)
- **Delta Panel** (response comparison)
- **Entropy Panel** (randomness analysis)
- **Workflow Panel** (macro recording/playback)

See [`ROADMAP_COMPETITIVE.md`](../../../ROADMAP_COMPETITIVE.md) for full roadmap.

---

## Accessibility

All panels meet **WCAG AA** accessibility standards:

- ✅ Keyboard navigation
- ✅ Screen reader support (ARIA labels)
- ✅ High contrast mode
- ✅ Font scaling (100%-200%)
- ✅ Reduced motion support
- ✅ Color vision deficiency modes

**Testing**: `apps/desktop-shell/tests/a11y.spec.ts`

---

## Performance

- **Virtualized rendering**: Handle 50,000+ flows without lag
- **Lazy loading**: Load flow details on-demand
- **Memory efficient**: Constant memory usage regardless of flow count
- **Fast search**: Indexed full-text search across all traffic

**Benchmarks**: Sub-100ms P95 latency for flow rendering

---

## Learn More

- [Desktop Shell README](../../../apps/desktop-shell/README.md)
- [Plugin Development Guide](../plugins/sdk-tutorial.md)
- [Security Architecture](../security/index.md)
- [Roadmap](../../../ROADMAP_COMPETITIVE.md)
