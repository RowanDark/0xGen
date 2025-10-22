# Configuration

0xgen reads configuration from a single resolved source that combines defaults,
optional configuration files, and environment variable overrides. This keeps the
platform easy to tune locally and in production deployments.

## Resolution order {#resolution-order}

1. Built-in defaults.
2. `~/.0xgen/config.toml` (optional).
3. `~/.glyph/config.toml` in the user's home directory (optional legacy fallback).
4. `./glyph.yml` in the current working directory (optional).
5. Environment variables beginning with `0XGEN_`.

Each subsequent source overrides values defined in the previous ones. Local
project configuration therefore beats the user-level TOML file, and environment
variables have the final say. When the loader falls back to `~/.glyph/config.toml`
it emits a one-time warning and still honours the legacy file so existing
installations keep working. Run `glyphctl config migrate` to copy the legacy
configuration into the new `~/.0xgen` directory.

## Supported fields {#supported-fields}

```yaml
server_addr: 127.0.0.1:50051
auth_token: supersecrettoken
output_dir: /out
proxy:
  enable: false
  addr: ""
  rules_path: ""
  history_path: ""
  ca_cert_path: ""
  ca_key_path: ""
```

The TOML representation uses matching keys and section names.

## Environment overrides {#environment-overrides}

The loader accepts the following variables:

| Variable | Description |
| --- | --- |
| `0XGEN_SERVER` | Overrides `server_addr`. |
| `0XGEN_AUTH_TOKEN` | Overrides `auth_token`. |
| `0XGEN_OUT` | Overrides `output_dir`. |
| `0XGEN_ENABLE_PROXY` / `0XGEN_PROXY_ENABLE` | Controls `proxy.enable`. |
| `0XGEN_PROXY_ADDR` | Overrides `proxy.addr`. |
| `0XGEN_PROXY_RULES` | Overrides `proxy.rules_path`. |
| `0XGEN_PROXY_HISTORY` | Overrides `proxy.history_path`. |
| `0XGEN_PROXY_CA_CERT` | Overrides `proxy.ca_cert_path`. |
| `0XGEN_PROXY_CA_KEY` | Overrides `proxy.ca_key_path`. |

All variables accept whitespace-trimmed values. Boolean variables treat `1`,
`true`, `yes`, and `on` as true, and `0`, `false`, `no`, and `off` as false. Legacy
`0XGEN_` variables continue to work for one release and emit a warning when used.

## Inspecting the resolved configuration {#inspect-the-resolved-configuration}

Run the following command to print the merged configuration as seen by
`glyphctl`:

```bash
$ glyphctl config print
server_addr: 127.0.0.1:50051
auth_token: supersecrettoken
output_dir: /out
proxy:
  enable: false
  addr: 
  rules_path: 
  history_path: 
  ca_cert_path: 
  ca_key_path: 
```

This output reflects every override the loader applied, making it easier to
confirm the active settings in environments where multiple sources are involved.
