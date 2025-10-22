---
search: false
---

# Crash reporting: redact, bundle, and share safely

0xgen's desktop shell occasionally encounters unrecoverable errors (panics in the
Rust backend or fatal renderer exceptions). When this happens we want to convert
"it crashed" into a bundle that maintainers can replay locally without shipping
sensitive customer data. This document describes the crash reporting pipeline
that fulfils the stability, accessibility, and privacy expectations captured in
issue #12.

## Goals

- Capture a deterministic crash bundle every time the desktop shell terminates
  unexpectedly.
- Preserve analyst privacy by redacting secrets and giving users final approval
  before anything leaves the workstation.
- Keep the workflow accessible: the review surface must be screen reader
  compatible and keyboard operable.
- Ensure the crash bundle can be replayed by maintainers to reproduce the
  failure without network access.

## Non-goals

- Shipping telemetry to a remote crash processing service. Bundles are meant to
  be saved locally and shared manually.
- Supporting partial failures (e.g. failed plugin runs). Those are handled by
  existing case replay tooling.

## Crash capture pipeline

1. **Fatal error detection** – Hook both the Rust panic handler and the
   JavaScript `window.onerror`/`unhandledrejection` surface. When triggered we
   stop spawning new work, flush the log buffer, and block the UI on the crash
   review screen.
2. **Minidump capture** – Use `dump_syms` compatible stack traces gathered from
   Rust backtraces and renderer source maps. We store them as UTF-8 encoded JSON
   snippets (`crash/minidump.json`) to avoid emitting binary artifacts that
   might accidentally get committed to the repository snapshot.
3. **Logs** – Pipe structured logs written through the `tracing` subscriber into
   an in-memory ring buffer. On crash, persist the last 10 000 lines to
   `crash/logs.ndjson` using newline-delimited JSON entries with timestamps and
   severity levels.
4. **Metrics snapshot** – Query the in-process metrics registry (the same data
   exposed by `/metrics`) and serialise it to `crash/metrics.prom`. This makes it
   possible to replay dashboards or run `promtool` locally.
5. **Environment manifest** – Record shell version, OS details, feature flags,
   and active plugins inside `crash/manifest.json` so maintainers know which
   build triggered the issue.

All files live inside a temporary directory. The collector ensures every output
is UTF-8 text, satisfying the “no binary files” guardrail while remaining easy to
inspect in diffs or via screen readers.

## Redaction and review UI

Sensitive payloads (API keys, tokens, secrets) are passed through the existing
redaction utility shared with the case exporter. Before the bundle can be
exported the user is presented with a modal that:

- Lists every file that will be included along with its byte size and a short
  description.
- Shows a diff-style preview of redactions, highlighting masked fields.
- Provides copy buttons for support tickets (“Crash ID”, “Bundle path”).

Users can expand each file to inspect the raw text. The UI follows our
accessibility guidelines: semantic headings, focus traps inside the modal, and
keyboard shortcuts for approve/cancel.

## Saving the bundle

The modal surfaces two actions:

1. **Save bundle** – Generates a `.tar.gz` archive containing the crash
   directory. The archive lives wherever the user chooses via the Tauri file
   dialog. We rely on `tar` + `flate2` in streaming mode, so the shell never
   buffers the whole bundle in memory.
2. **Discard** – Deletes the crash directory and exits the application without
   leaving behind artefacts.

Because the crash directory only contains text files, the resulting archive is
safe to attach to bug reports without tripping repository binary file checks.

## Maintainer workflow

Maintainers can reproduce the crash by unpacking the archive and running the new
`0xgenctl crash replay /path/to/bundle` helper. The command spins up the shell in
replay mode, injects the captured metrics/logs, and loads the minidump JSON to
reconstruct the call stack. Documentation for the replay flow will live alongside
other support guides.

## Acceptance criteria

- Every fatal error surfaces the crash review modal with populated bundle
  metadata.
- Users explicitly approve exporting the archive and can inspect the redacted
  contents prior to saving.
- Maintainers can run the replay helper with the archive and reproduce the
  failure locally.
- All generated artefacts are UTF-8 text files; no binary blobs are written.

## Follow-up tasks

- Document the replay CLI in the support playbook.
- Add CI coverage that exercises the panic hook and asserts bundle generation
  works on macOS, Linux, and Windows runners.
