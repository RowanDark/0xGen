# Updater channels and rollback

0xgen ships a built-in update service for both the desktop shell and the `0xgenctl`
CLI. This guide documents how we stage releases to the stable and beta channels,
how delta packages are produced, and how clients verify, apply, and roll back
updates.

## Release channels {#release-channels}

0xgen maintains two distribution channels:

- **Stable** — the default for production usage. Releases land here after they
  complete smoke tests on every platform and pass the release checklist.
- **Beta** — opt-in builds for early adopters. Beta publishes as soon as the
  release automation finishes assembling artifacts so we can surface regressions
  before promoting the build to stable.

### Desktop shell channel selection {#desktop-channel-selection}

The desktop application exposes the active channel on the Settings → Updates
panel. Users can toggle between Stable and Beta; a confirmation dialog explains
that switching channels triggers an immediate update check and may download
additional resources. The choice persists in the per-user configuration file so
future auto-checks continue to poll the chosen channel.

### CLI channel flag {#cli-channel-flag}

`0xgenctl` exposes a `self-update` command that accepts a
`--channel=<stable|beta>` flag. The flag defaults to the stored preference and
acts as a one-shot override for the current invocation. To change the persisted
channel run `0xgenctl self-update channel <stable|beta>`; we store the result in
`~/.config/0xgenctl/updater.json` alongside bookkeeping data for rollback. The
CLI prints the active channel when invoked as `0xgenctl self-update channel`.

The updater keeps a copy of the previous binary in the same configuration
directory. `0xgenctl self-update --rollback` replaces the current executable
with that cached build and flips the stored channel back to `stable` as a safety
valve.

Both the desktop and CLI clients include the channel name in the update request
headers. The update API uses the header to return the latest manifest for that
cohort, ensuring beta-only builds never bleed into stable users.

## Delta update packaging {#delta-update-packaging}

Release automation builds delta archives in addition to the full installers.
Delta support currently covers:

- **macOS** — we generate binary patches between signed `.app` bundles using the
  `bsdiff` algorithm via `sparkle` tooling.
- **Windows** — MSI packages embed a Patch creation transform so the updater can
  apply `.msp` deltas in place.
- **Linux** — AppImage releases ship with `zsync` metadata to enable efficient
  block-level deltas.

During release creation we compare the pending tag against the previous stable
and beta tags. If the delta exceeds 60% of the full archive size or the platform
is not in the supported list above, we fall back to publishing the full
installer and mark the manifest accordingly. Clients honour the flag and skip
delta downloads when the manifest declares `delta_available = false`.

## Signed manifests and verification {#signed-manifests}

Each channel publishes a JSON manifest that enumerates the available build,
supported platforms, and the cryptographic checksums for both delta and full
artifacts. The release pipeline signs the manifest with the 0xgen release key
using `minisign`. Clients verify the detached signature before trusting the
metadata. Verification failure aborts the update and surfaces an actionable
error that points users to the status page.

Clients also validate individual artifacts by hashing downloads and comparing the
values against the manifest. Any mismatch triggers an automatic retry from the
alternate CDN endpoint. Persistent mismatches block the update entirely and the
UI links to troubleshooting documentation.

## Automatic rollback {#automatic-rollback}

Installers retain the previous application bundle alongside the newly applied
version. After applying an update the client performs a readiness check that
includes:

1. Verifying the executable starts within a 30-second timeout.
2. Confirming the local plugin registry loads.
3. Checking telemetry heartbeats for five minutes (desktop) or one successful
   CLI run (invoked via `0xgenctl --version`).

If any verification step fails, the updater restores the prior bundle, replays
the manifest signature checks to ensure integrity, and switches the auto-update
channel back to `stable` as a safety valve. Users receive a toast (desktop) or
stderr output (CLI) explaining that the rollback completed and that diagnostics
were uploaded for triage.

The rollback path is also exposed manually: the desktop UI offers a "Restore
previous version" button on the Updates panel, while `0xgenctl self-update`
accepts `--rollback` to revert to the cached build.

## Release engineering checklist additions {#release-engineering}

When cutting a release, append the following steps to the standard checklist:

1. Populate `packaging/updater/` with JSON channel definitions that point at the
   release artifacts. See `packaging/updater/README.md` for the schema.
2. Export the base64-encoded ed25519 private key as `0XGEN_UPDATER_SIGNING_KEY`.
3. Run `make updater:build-manifests` to produce signed manifests for both
   channels.
4. Inspect `out/updater/` to confirm delta packages were generated for every
   supported platform and that the manifest flags fallback builds appropriately.
5. Upload the delta and full artifacts to the CDN and publish the manifests to
   `/updates/<channel>/manifest.json` alongside the detached signatures.
6. Smoke-test `0xgenctl self-update --channel beta` and a desktop beta install on
   macOS, Windows, and Linux before promoting the build to stable.
7. Archive the release telemetry in the incident response dashboard so we can
   trace rollbacks.

Following this checklist keeps the auto-update surface safe even as we roll out
beta features aggressively.
