# Threat Model

Glyph runs untrusted analysis plugins while aggregating findings into signed,
reproducible reports. This one-pager highlights the security posture that
contributors and operators should keep in mind when extending the platform.

## Security goals and assumptions

* Keep the Glyph daemon (`glyphd`) and control surface (`glyphctl`) resilient to
  compromised plugins.
* Ensure every finding and release artifact has verifiable provenance.
* Allow operators to reproduce a reported issue from stored artifacts without
  re-running untrusted code.
* Assume attackers can supply arbitrary plugin binaries and task inputs but do
  not control the host operating system.

## Plugin isolation and resource limits

Plugins execute in dedicated subprocesses with minimal privileges. Each run is
assigned a temporary working directory and restricted environment variables so
writes cannot escape the sandbox by default. The supervisor applies CPU, memory,
and wall-clock limits through POSIX `RLIMIT` values exposed via
[`runner.Config`](../internal/plugins/runner/runner.go). Exceeding a limit
terminates the plugin process group and records a
`glyph.supervisor.termination` event so operators can audit resource abuse.

## Network capabilities

Glyph starts in a "no network" posture. Plugins must declare explicit
capabilities such as `CAP_HTTP_ACTIVE` or `CAP_WS` in their manifest before the
runtime wires up outbound networking helpers. Operators can leave the
`proxy.enable` setting disabled (the default) to block all traffic, or provide a
policy-controlled proxy to mediate active scanning. Capability-gated networking
ensures that a plugin without the relevant permission cannot reach the network
layer at all.

## Provenance and signing

Every release artifact ships with SLSA v3 provenance that can be verified using
`slsa-verifier`, as described in [`docs/security/provenance.md`](security/provenance.md).
Glyph's supervisors and plugins also emit structured findings that include the
plugin identity, configuration fingerprints, and hashes of harvested evidence.
This metadata allows downstream systems to prove which signed binary generated a
finding and to trace it back to the exact task invocation.

## Reproducing reports from artifacts

The default workflow stores logs and JSONL transcripts for each run under the
`out/` directory. To reproduce a report without executing untrusted plugins:

1. Fetch the archived artifacts (for example, the `out/findings.jsonl` and
   `out/report.html` bundles produced in CI).
2. Validate the provenance or checksums attached to the archive.
3. Use the reference copies under [`examples/quickstart/`](../examples/quickstart)
   as golden inputs and diff them against the downloaded artifacts.
4. Render the HTML dashboard by opening `out/report.html`, or feed the JSONL
   data into local tooling for inspection.

Because every run captures deterministic artifacts, maintainers can inspect and
share the exact evidence that triggered a report without rerunning the original
plugins.
