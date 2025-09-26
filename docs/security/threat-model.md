# Threat Model

Glyph runs untrusted analysis plugins while aggregating findings into signed,
reproducible reports. This document captures the security goals, assumptions, and
controls that underpin the default deployment model.

## Goals and assumptions

- Keep the Glyph daemon (`glyphd`) and control surface (`glyphctl`) resilient to
  compromised plugins.
- Ensure every finding and release artifact has verifiable provenance.
- Allow operators to reproduce a reported issue from stored artifacts without
  re-running untrusted code.
- Assume attackers can supply arbitrary plugin binaries and task inputs but do not
  control the host operating system.

## Plugin isolation and resource limits

Plugins execute in dedicated subprocesses with strict resource limits. Each run is
assigned a temporary working directory and constrained environment variables so writes
cannot escape the sandbox by default. The supervisor applies CPU, memory, and
wall-clock limits through POSIX `RLIMIT` values exposed via
[`runner.Config`]({{ config.repo_url }}/blob/main/internal/plugins/runner/runner.go). Exceeding a limit terminates
the plugin process group and records a `glyph.supervisor.termination` event so
operators can audit resource abuse.

The supervisor captures termination reasons and emits structured metadata such as the
task ID, CPU/heap usage, and configured timeouts. Operations teams can trace why a
plugin stopped and correlate the event with downstream automation.

## Network posture

Glyph starts in a "no network" posture. The built-in configuration keeps
`proxy.enable` set to `false`, leaving Glyph without outbound network access unless
operators explicitly toggle interception through `glyph.yml` or environment overrides.
When the proxy is enabled it must be pointed at explicit rule and history paths,
reinforcing intentional deployment rather than accidental active scanning.

Capabilities declared in a plugin's manifest (for example `CAP_HTTP_ACTIVE` or
`CAP_WS`) gate access to outbound helpers exposed by the host. A plugin without the
relevant capability cannot reach the network layer at all.

## Finding provenance

Every release artifact ships with SLSA v3 provenance that can be verified using
`slsa-verifier`, as described in [Build Provenance](provenance.md). Glyph's supervisors
and plugins also emit structured findings that include the plugin identity,
configuration fingerprints, and hashes of harvested evidence. This metadata allows
downstream systems to prove which signed binary generated a finding and to trace it
back to the exact task invocation.

## Reproducing reports from artifacts

The default workflow stores logs and JSONL transcripts for each run under the `out/`
directory. To reproduce a report without executing untrusted plugins:

1. Fetch the archived artifacts (for example, the `out/findings.jsonl` and
   `out/report.html` bundles produced in CI).
2. Validate the provenance or checksums attached to the archive.
3. Use the reference copies under [`examples/quickstart/`]({{ config.repo_url }}/tree/main/examples/quickstart)
   as golden inputs and diff them against the downloaded artifacts.
4. Render the HTML dashboard by opening `out/report.html`, or feed the JSONL data into
   local tooling for inspection.

Because every run captures deterministic artifacts, maintainers can inspect and share
the exact evidence that triggered a report without rerunning the original plugins.
