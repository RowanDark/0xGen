# Security Overview

Glyph's security model balances powerful automation with strict guardrails that keep
operators in control. This section consolidates resources for security reviewers and
incident responders.

## Vulnerability reporting {#vulnerability-reporting}

Please follow the process documented in [SECURITY.md]({{ config.repo_url }}/blob/main/SECURITY.md) when reporting
vulnerabilities. The security team monitors the disclosed channels and coordinates
fixes as quickly as possible. Include reproduction steps, impacted versions, and any
supporting artifacts.

## Threat model and provenance {#threat-model-and-provenance}

The [threat model](threat-model.md) explains how Glyph isolates untrusted plugins,
limits network access, and captures audit trails for every run. Combine it with the
[build provenance](provenance.md) and [supply-chain hardening](supply-chain.md)
guides to verify that downloaded binaries and containers were produced by the
official CI pipelines and signed by trusted automation.

## Hardening checklist {#hardening-checklist}

- Disable the proxy (`proxy.enable: false`) unless you need active interception.
- Grant plugins only the capabilities listed in their manifests.
- Rotate the Glyph authentication token regularly and prefer long, randomly generated
  values.
- Archive the `out/` artifacts from CI or production runs to make incident response
  reproducible.

For deeper dives into plugin isolation, report reproduction, and release verification,
explore the sub-pages linked in the navigation menu.
