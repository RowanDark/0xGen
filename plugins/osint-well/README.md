# OSINT Well

OSINT Well wraps [OWASP Amass](https://github.com/owasp-amass/amass) to surface open-source intelligence such as subdomains and infrastructure relationships. The plugin intentionally defaults to passive reconnaissance so that it can be executed safely in shared or sensitive environments.

## Installation

1. Install the Amass binary (v3.23.0 or newer is recommended) and ensure it is available on your `PATH`.
2. Build `glyphctl` if you plan to orchestrate plugins locally:
   ```bash
   go build ./cmd/glyphctl
   ```
3. (Optional) Export `0XGEN_OUT` to control where normalized assets are written. The default is `/out`.

## Passive vs. active enumeration

`amass enum` supports both passive and active techniques. Passive mode only queries third-party data sources (e.g. certificate transparency, passive DNS) and does not touch the target's infrastructure. Active mode may probe DNS records, perform brute-force name discovery, and send network traffic to discovered hosts.

This plugin's wrapper keeps executions passive by default to minimize risk:

- `run_amass.sh` enforces `amass enum --passive`.
- Extra flags forwarded to Amass should preserve passive behaviour. Avoid enabling brute force (`-brute`), active port scanning, or other intrusive features unless you have explicit authorization.
- If you need active enumeration, run Amass manually and then feed the results into `normalize.js` for post-processing.

## Usage

### Quick wrapper

```
./plugins/osint-well/run_amass.sh -d example.com
```

Arguments:

- `-d / --domain` – target domain (required).
- `-o / --out` – destination JSONL file. Defaults to `${0XGEN_OUT:-/out}/assets.jsonl`.
- `-b / --binary` – override the Amass binary path.
- `--` – pass through additional passive-safe flags to Amass.

The script writes Amass JSON to a temporary file, invokes the normalizer, and reports where the JSONL landed.

### Normalizing previously captured output

If you already have Amass NDJSON (from `amass enum ... -json results.json`), convert it with:

```
node plugins/osint-well/normalize.js path/to/amass.json existing-assets.jsonl
```

Each line of the output will look like:

```
{"type":"subdomain","value":"foo.example.com","source":"amass","ts":"2024-05-01T00:00:00Z"}
```

The normalizer deduplicates subdomains, keeps the earliest timestamp when duplicates are encountered, and guarantees deterministic sorting for stable diffs.

### Working with `glyphctl`

You can also drive the plugin through `glyphctl` once it is compiled:

```
./glyphctl osint-well --domain example.com --out ./out/assets.jsonl
```

To stay passive, avoid adding active enumeration flags via `--args`. When in doubt, consult the [Amass user guide](https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md) for the distinction between passive and active options.

## Testing the normalizer

A canned Amass sample lives in `plugins/osint-well/tests/amass_passive.json`. Run the following to verify normalisation without hitting the network:

```
go test ./plugins/osint-well
```

The test harness executes `normalize.js` against the fixture and asserts that a valid `assets.jsonl` is produced.
