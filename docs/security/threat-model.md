# Threat Model Overview

Glyph is designed to run untrusted plugins while protecting the host operator and
keeping findings attributable. This document summarises the guardrails that ship with
the default configuration.

## Plugin sandboxing

Glyph runs every plugin in a dedicated subprocess with strict resource limits. The
sandbox code assigns each run a temporary working directory and constrains `HOME`,
`TMPDIR`, and the inherited `PATH` to that directory so plugins cannot write outside
of their scratch space by default. [`runner.Config`](../../internal/plugins/runner/runner.go)
exposes CPU-, memory-, and wall-clock limits that are enforced through POSIX
`RLIMIT` calls before the plugin starts. Exceeding these limits terminates the process
group and propagates an error back to the supervisor.

The supervisor captures the termination reason and emits a
`glyph.supervisor.termination` finding containing structured metadata such as the task
ID, CPU/heap usage, and configured timeouts. Operations teams can trace why a plugin
stopped and correlate the event with downstream automation.

## Network posture

The glyphd proxy is disabled by default. The built-in configuration keeps
`proxy.enable` set to `false`, leaving Glyph in a no-network posture unless operators
explicitly toggle interception through `glyph.yml` or environment overrides. When the
proxy is enabled it must be pointed at explicit rule and history paths, reinforcing
intentional deployment rather than accidental active scanning.

## Finding provenance

Findings emitted by core detectors include enough metadata to audit their origin.
Seer annotates each result with the pattern identifier, the number of characters
matched, entropy measurements, and the redacted evidence that triggered the alert.
Combined with the supervisor termination findings above, teams can establish an
end-to-end paper trail for every automated decision Glyph makes.
