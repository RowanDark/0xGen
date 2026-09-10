# Plugin Security Guide

This guide summarizes the expectations for 0xgen plugins and provides practical
patterns to keep new integrations safe.

## Design principles

* **Use the broker APIs** for outbound HTTP, credential access, and artifact
  exchange. They add auditing, authorization, and uniform logging.
* **Avoid raw filesystem access**. Plugins should only write to their allocated
  workspace and must not read arbitrary host paths or environment variables that
  are unrelated to their task.
* **Do not open raw outbound sockets.** The sandbox does not currently
  filter or proxy plugin network traffic - a plugin that dials out directly
  will succeed regardless of its declared capabilities. Route egress through
  the broker APIs anyway: it's the only path that gets auditing, and the
  sandbox's lack of network filtering is a known gap, not a guarantee that
  direct sockets stay available or safe (see [Sandbox internals](#sandbox-internals)).
* **Fail closed.** Handle broker errors, timeouts, and validation failures by
  terminating gracefully rather than retrying indefinitely.
* **Keep dependencies minimal and pinned.** Rely on reproducible builds, lock
  files, and integrity verification to reduce supply-chain exposure.

## Sandbox internals

Every non-`trusted` plugin runs inside a chroot with a seccomp-bpf syscall
denylist and a privilege drop to an unprivileged uid/gid; there is no
per-plugin sandbox configuration in the manifest. See
[README.md → Plugin Security](README.md#plugin-security) for exactly which
controls apply, which syscalls are blocked, and what is *not* enforced
(notably: network access). Running `0xgend` as root is required for the
sandbox to function at all - see
[INSTALL.md → Plugin Sandbox Requirements](INSTALL.md#plugin-sandbox-requirements-linux).

## Recommended development workflow

1. Start from the minimal plugin skeleton below.
2. Declare capabilities explicitly in `manifest.json`.
3. Use the SDK helpers for broker communication and structured logging.
4. Cover both success and failure scenarios in integration tests.
5. Run `make lint` and `make test` (or the plugin's equivalent scripts) before
   sending a PR.

## Example manifest

```json
{
  "name": "oxg-example-plugin",
  "version": "0.1.0",
  "entry": "example-plugin",
  "artifact": "plugins/example-plugin/main.go",
  "capabilities": ["CAP_EMIT_FINDINGS", "CAP_HTTP_PASSIVE"],
  "signature": {
    "signature": "main.go.sig",
    "publicKey": "../keys/0xgen-plugin.pub"
  }
}
```

`capabilities` is a flat list of capability names (see
`plugins.AllowedCapabilities()` for the full set); there is no per-manifest
`sandbox` block - every non-`trusted` plugin gets the same fixed sandbox
described in [Sandbox internals](#sandbox-internals) above.

## Minimal secure skeleton

```bash
#!/usr/bin/env bash
set -euo pipefail

# Use broker-provided workspace paths
WORKDIR="${0XGEN_WORKSPACE:?missing workspace}"
LOG_PATH="$WORKDIR/run.log"

log() {
  printf '%s\t%s\n' "$(date -Is)" "$*" | tee -a "$LOG_PATH"
}

log "starting example plugin"

# Fetch tasks via the SDK rather than raw curl
if ! 0xgenctl broker task pull --out "$WORKDIR/task.json"; then
  log "failed to retrieve task"; exit 1
fi

# Process data and emit findings
python3 plugin/main.py "$WORKDIR/task.json"
```

The script uses broker commands instead of reading environment variables or
making unaudited network calls. Any additional tooling should live inside the
sandbox and avoid `sudo`, host mounts, or direct Docker API access.

## Testing checklist

* Run unit tests with mocked broker responses.
* Execute integration tests in the same container image used in production.
* Validate manifests with `npm -s i -g ajv-cli@5.0.0 && ajv validate -s plugins/manifest.schema.json -d plugins/<your-plugin>/manifest.json`.
* Inspect logs for unexpected environment variables, network destinations, or
  filesystem paths.
* Confirm that findings redact secrets and personally identifiable information.

## Further reading

* [0xgen threat model](THREAT_MODEL.md)
* [Security policy](SECURITY.md)
* [SDK documentation](docs/sdk/README.md)
