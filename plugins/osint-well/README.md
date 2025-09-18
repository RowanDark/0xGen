# OSINT Well

OSINT Well orchestrates Amass to enrich Glyph investigations with open-source intelligence such as subdomains and infrastructure relationships.

## Capabilities
- `CAP_EMIT_FINDINGS`
- `CAP_STORAGE`

## Getting started
1. Ensure Amass is installed locally and available on your `PATH`.
2. Run the helper script to capture Amass output for a test domain:
   ```bash
   ./run_amass.sh example.com
   ```
3. Normalize and feed the results into Glyph findings in `plugin.js`.

`tests/sample_fixture.json` can store sanitized Amass outputs once integration begins.
