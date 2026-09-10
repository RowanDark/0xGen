# 0xgen Threat Model

This document summarizes the security assumptions, major attack surfaces, and the
controls that 0xgen relies on today. It is intended to help contributors reason
about changes, plugin authors understand the runtime expectations, and auditors
navigate the project.

## High-level assumptions

* 0xgen deployments run inside trusted infrastructure managed by the operator.
  We assume the host OS, container runtime, and CI pipelines are hardened and
  patched.
* Secrets such as API tokens, webhook credentials, or private keys are supplied
  by the operator and must not be exfiltrated by plugins.
* Plugins execute within constrained sandboxes (containers, browser contexts, or
  subprocesses) and should treat any data originating from remote systems as
  hostile until validated.
* Network egress from plugins is tightly controlled. When external connectivity
  is required, it should be routed through the 0xgen broker APIs or other
  audited proxies.

## Threat scenarios

### Plugin compromise

Malicious or compromised plugins can attempt to exfiltrate data, tamper with
findings, or attack the orchestrator.

* **Controls**: plugins run with least-privilege, communicate through defined
  gRPC/HTTP APIs, and are required to follow the [plugin guidance](PLUGIN_GUIDE.md).
  The orchestrator validates manifests and enforces allow-listed capabilities.
* **Recommendations**: avoid reading arbitrary environment variables or host
  filesystem paths, and never ship hard-coded credentials. Sensitive data should
  transit via broker APIs with auditing.

### Crawler abuse

Playwright-based crawlers (e.g. Excavator) navigate untrusted content that may
attempt drive-by attacks or trigger resource exhaustion.

* **Controls**: crawler containers run with seccomp profiles, disabled writable
  mounts, and explicit navigation timeouts. Rendered artifacts are treated as
  untrusted input downstream.
* **Recommendations**: keep Playwright patched, and use detached browser
  contexts so compromised tabs cannot pivot to the host.

### Supply-chain risk

Dependencies, build tooling, or plugin updates can introduce vulnerabilities or
backdoors.

* **Controls**: release artifacts are signed, SBOMs are published, and the
  repository enables automated dependency review and SLSA provenance attestation.
* **Recommendations**: pin versions in manifests, run `make sbom`, and review
  diffs in vendor directories or generated code before merging.

### Plugin build-time trust boundary

`0xgend` compiles plugin source with `go build` before the sandbox
described below even exists to contain it: the build itself runs as the
daemon user, outside any sandbox.

* **Controls**: before building, the launcher (`internal/plugins/launcher/launcher.go`)
  verifies the plugin artifact's hash against a signed allowlist and, unless
  explicitly skipped for `trusted: true` development plugins, verifies a
  cosign signature over the source. The `go build` invocation itself runs
  with `CGO_ENABLED=0` (closing the `#cgo LDFLAGS`/`#cgo CFLAGS` code-execution
  vector), `GOFLAGS=-mod=readonly` (so a build cannot silently add
  dependencies outside `go.sum`), and `GOTOOLCHAIN=local` (so a plugin's
  `go.mod` cannot trigger downloading and running a different Go toolchain).
  The subprocess environment is scrubbed to a fixed `PATH` plus a short
  allowlist of toolchain variables (`HOME`, `GOCACHE`, `GOPATH`, etc.); daemon
  secrets and the rest of the daemon's environment are not forwarded to the
  build.
* **What this does not provide**: verifying a signature and then compiling
  the verified source is not equivalent to running untrusted code in a
  sandbox. The Go compiler and standard library are a large trusted
  computing base, and `go build` executes with the daemon's filesystem and
  process privileges (network access, ability to read/write anything the
  daemon user can). A plugin author whose signing key is compromised, or
  who the operator does not fully trust, can affect the build host through
  any means available to a Go program running as that user — not just the
  narrower `#cgo` vector the env-scrubbing above closes. Treat the signature
  allowlist as authenticity and change-detection, not as a sandbox
  boundary: **plugin source is trusted at build time**.
* **Recommendations**: only sign plugins from authors you trust to run
  arbitrary code as the `0xgend` user. Do not treat `ALLOWLIST` entries or
  cosign signatures as a substitute for reviewing plugin source. The
  long-term fix tracked for this gap is distributing plugins as precompiled,
  signed artifacts so no build happens on the operator's machine at all;
  until then, this section is the accurate threat model for the build step.

### Sandbox escapes

Adversaries may attempt to escape the process sandbox hosting a plugin to
compromise the 0xgend host.

* **Controls**: non-`trusted` plugins run inside a chroot with a
  seccomp-bpf syscall denylist and a privilege drop to an unprivileged
  uid/gid (see [README.md → Plugin Security](README.md#plugin-security) for
  the exact mechanisms and what they do not cover). This is a chroot-based
  process sandbox, not a container or VM boundary, and the chroot is not
  mounted read-only. Building and entering it requires 0xgend to run as
  root.
* **Recommendations**: do not grant extra capabilities in manifests, keep
  `trusted: true` for local development only, and ensure unit tests include
  negative cases for privilege escalation attempts (e.g.
  `internal/plugins/runner/sandboxcmd`'s seccomp and capability-drop tests).

### Man-in-the-middle (MITM)

Interception of network traffic between 0xgen components could allow tampering
with findings or plugin coordination.

* **Controls**: internal communication uses mutual TLS, and the orchestrator
  validates certificates pinned to the deployment.
* **Recommendations**: avoid disabling TLS verification during debugging, and
  rotate certificates when revoking plugin access.

### Server-side request forgery (SSRF) / XML external entity (XXE)

Plugins that fetch remote resources or parse XML may be coerced into making
requests to internal services or leaking local files.

* **Controls**: broker APIs validate destinations, redact sensitive headers, and
  enforce response size limits. XML parsers in the SDK disable external entity
  resolution by default.
* **Recommendations**: never construct URLs from untrusted input without
  validation, and prefer the broker HTTP client helpers over raw sockets.

## Residual risks

* Operators must monitor plugin logs and metrics to detect abuse.
* Sandboxing relies on chroot, seccomp, and privilege dropping in the same
  kernel as the host; a kernel exploit can bypass isolation until patched.
  Namespaces (mount, PID, user) are not used, so isolation is weaker than a
  container or VM boundary.
* The sandbox does not restrict plugin network egress at all. 0xgen assumes
  the network perimeter enforces egress filtering; without one, a compromised
  or malicious plugin can reach anything the host can reach.

## Reporting

Potential gaps or new attack surfaces should be reported following the
[security policy](SECURITY.md).
