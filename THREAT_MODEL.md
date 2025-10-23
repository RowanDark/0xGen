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

### Sandbox escapes

Adversaries may attempt to escape container or VM sandboxes hosting plugins to
compromise the orchestrator host.

* **Controls**: containers run as non-root, with dropped capabilities and
  read-only filesystems. Host mounts only expose plugin-specific workspaces.
* **Recommendations**: do not grant extra privileges in manifests, and ensure
  unit tests include negative cases for privilege escalation attempts.

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
* Sandboxing relies on container runtime hardening; a kernel exploit can bypass
  isolation until patched.
* 0xgen assumes the network perimeter enforces egress filtering. Lack of
  filtering increases the blast radius of plugin compromise.

## Reporting

Potential gaps or new attack surfaces should be reported following the
[security policy](SECURITY.md).
