---
search: false
---

# Sprint Plan: Galdr, Excavator, Scribe, Seer, and OSINT Well

## Overview
This sprint focuses on hardening the Galdr proxy foundation while delivering first-pass capabilities for crawling, reporting, secrets detection, and passive OSINT enrichment. Workstreams are listed in priority order and should ship iteratively so later tasks can build on earlier outputs.

---

## 1. Galdr Proxy — MVP++ Hardening (Foundation)
**Goal:** Deliver reliable HTTP/1.x interception and modification with HTTPS MITM support, plus lay architectural hooks for future HTTP/2/3 and WebSocket processing.

**Scope & Tasks**
- Implement an HTTP/1.x forward proxy using `net/http` and `httputil.ReverseProxy`.
  - Use `Director` for deterministic request edits and `ModifyResponse` for response edits.
  - Maintain per-request context to ensure edits are applied predictably.
- Add HTTPS interception with on-the-fly leaf certificate generation signed by a self-signed CA created at first run.
  - Provide a CLI option to export the CA certificate and author documentation for installing the CA quickly.
- Prepare for HTTP/2 and HTTP/3.
  - Leverage Go's native HTTP/2 support.
  - Gate future HTTP/3 work behind a build tag and plan to use `quic-go/http3` once ready.
- Ensure WebSocket traffic passes through using a minimal proxy handler (e.g., `koding/websocketproxy`). Editing hooks can follow later.
- Ship an end-to-end smoke test: run one request through the proxy, assert a header rewrite occurs, and verify a history JSONL entry is written.

**Deliverables**
- Hardened proxy implementation and tests.
- CLI affordances for CA export and install instructions.
- Codex-ready issue title: `galdr: MVP++ (HTTP/1.x intercept + HTTPS MITM + WS passthrough)`.

---

## 2. Excavator — Playwright Starter to v0.1 Crawler
**Goal:** Crawl a single origin reliably, capturing links and simple JavaScript artifacts.

**Scope & Tasks**
- Build a headless Playwright crawler that waits for network idle and respects conservative timeouts.
- Normalize, deduplicate, and bound discovered URLs by depth and host.
- Collect simple artifacts: page links, script URLs, and surfaced endpoints.
- Emit a structured JSON report and add a golden test to lock behavior.
- Optionally integrate a CI workflow that runs the crawler against `example.com` only.

**Deliverables**
- Playwright-based crawler with configuration knobs.
- Golden test fixture and optional CI step.
- Codex-ready issue title: `excavator: v0.1 crawl (links+scripts, depth limits, golden test)`.

---

## 3. Scribe — Reporting from Findings JSONL
**Goal:** Transform findings JSONL files into a human-friendly Markdown report.

**Scope & Tasks**
- Implement `0xgenctl report --input /out/findings.jsonl --out /out/report.md`.
- Summarize totals by severity, highlight top targets, and include a table of the most recent findings.
- Create a golden test that validates the generated Markdown.
- Plan future enhancements such as automated triage, but keep scope focused on deterministic reporting.

**Deliverables**
- Reporting CLI with documentation.
- Golden test artifacts.
- Codex-ready issue title: `scribe: v0.1 markdown report`.

---

## 4. Seer — Secrets/PII Detector (Passive)
**Goal:** Provide baseline secrets detection combining regex signatures and entropy heuristics while minimizing false positives.

**Scope & Tasks**
- Implement regex detection for common credentials (AWS keys, Slack tokens, generic API keys, emails, etc.).
- Layer entropy scoring to catch high-entropy tokens and suppress low-risk noise.
- Add allowlisting for patterns or domains to tune false positives.
- Redact evidence output to hide most token characters.

**Deliverables**
- Passive scanning module with tunable knobs.
- Documentation for allowlists and evidence redaction.
- Codex-ready issue title: `seer: v0.1 (regex+entropy, allowlists, redacted evidence)`.

---

## 5. OSINT Well — Amass Wrapper (Passive Mode First)
**Goal:** Wrap Amass passive enumeration and normalize results for downstream tooling.

**Scope & Tasks**
- Execute `amass enum -passive -d <domain>` and capture outputs.
- Normalize assets into `/out/assets.jsonl`.
- Provide usage documentation and sample output.

**Deliverables**
- Passive Amass integration and JSONL normalizer.
- Documentation and sample artifacts.
- Codex-ready issue title: `osint-well: passive amass wrapper + normalizer`.

---

## Guardrails & Nice-to-Haves
- Keep proxy functionality disabled by default in tests; require explicit opt-in (e.g., `--enable-proxy` or environment flag).
- Immediately surface proxy/gRPC errors so failures are visible.
- Continue gating HTTP/3 behind feature flags until the implementation stabilizes (`quic-go/http3`).
- Plan for future CORS/preflight coverage referencing MDN guidance.
- Provide performance controls (timeouts, concurrency limits) for both proxy and crawler modules.
- Preserve CI expectations: Go race detector, 2-OS build matrix, and stable lint v2 configuration.

---

## Order of Operations
1. Galdr Proxy hardening & tests.
2. Excavator crawler foundation & golden tests.
3. Scribe reporting CLI & golden tests.
4. Seer passive secrets detection.
5. OSINT Well passive wrapper & normalization.
6. Apply guardrails and CI requirements across workstreams throughout the sprint.

