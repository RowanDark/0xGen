# Updater channel configuration

`make updater:build-manifests` reads JSON channel definitions from this
directory and produces signed manifests under `out/updater/<channel>/`. Each
`*.json` file must match the following schema:

```json
{
  "channel": "stable",
  "version": "1.2.3",
  "notes_url": "https://glyph.dev/releases/1.2.3",
  "builds": [
    {
      "os": "linux",
      "arch": "amd64",
      "full": {
        "url": "https://cdn.glyph.dev/updates/stable/linux-amd64/glyphctl.tar.gz",
        "path": "../../out/dist/linux-amd64/glyphctl.tar.gz",
        "sha256": "optional sha override"
      },
      "delta": {
        "from_version": "1.2.2",
        "url": "https://cdn.glyph.dev/updates/stable/linux-amd64/glyphctl-1.2.2-1.2.3.patch",
        "path": "../../out/dist/linux-amd64/glyphctl-1.2.2-1.2.3.patch"
      }
    }
  ]
}
```

- `channel` must be either `stable` or `beta`.
- `version` is the semantic version that the manifest promotes for the channel.
- `notes_url` is optional.
- Each `build` entry must provide a `full` artifact. The `url` is written to the
  manifest. If `sha256` is omitted the build script hashes `path` to compute it.
- `delta` entries are optional. They must include `from_version` and `url`, and
  inherit the same checksum behaviour as `full`.

During signing the script expects a base64-encoded ed25519 private key in the
`0XGEN_UPDATER_SIGNING_KEY` environment variable. This key must match the public
key baked into the updater clients.

Files ending in `.example.json` are ignored so you can keep templates in the
repository without impacting release builds.
