# Configuration

Glyph reads configuration from a single resolved source that combines defaults,
optional configuration files, and environment variable overrides. This keeps the
platform easy to tune locally and in production deployments.

## Resolution order {#resolution-order}

1. Built-in defaults.
2. `~/.glyph/config.toml` (optional).
3. `./glyph.yml` in the current working directory (optional).
4. Environment variables beginning with `GLYPH_`.

Each subsequent source overrides values defined in the previous ones. Local
project configuration therefore beats the user-level TOML file, and environment
variables have the final say.

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
| `GLYPH_SERVER` | Overrides `server_addr`. |
| `GLYPH_AUTH_TOKEN` | Overrides `auth_token`. |
| `GLYPH_OUT` | Overrides `output_dir`. |
| `GLYPH_ENABLE_PROXY` / `GLYPH_PROXY_ENABLE` | Controls `proxy.enable`. |
| `GLYPH_PROXY_ADDR` | Overrides `proxy.addr`. |
| `GLYPH_PROXY_RULES` | Overrides `proxy.rules_path`. |
| `GLYPH_PROXY_HISTORY` | Overrides `proxy.history_path`. |
| `GLYPH_PROXY_CA_CERT` | Overrides `proxy.ca_cert_path`. |
| `GLYPH_PROXY_CA_KEY` | Overrides `proxy.ca_key_path`. |

All variables accept whitespace-trimmed values. Boolean variables treat `1`,
`true`, `yes`, and `on` as true, and `0`, `false`, `no`, and `off` as false.

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
