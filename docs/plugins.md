# Plugin Roster

The following plugins form the foundation of the Glyph platform. Each directory under `plugins/` contains a manifest, stub implementation, documentation, and test fixtures to accelerate future development.

| Plugin | Description |
| ------ | ----------- |
| `galdr-proxy` | Proxy ingress layer that streams HTTP flows into Glyph for collaborative analysis. |
| `cartographer` | Surface mapper that catalogs hosts, endpoints, and assets discovered across crawlers. |
| `excavator` | Playwright-powered crawler starter that captures links and scripts from target applications. |
| `raider` | Active testing coordinator that executes offensive playbooks against prioritized targets. |
| `osint-well` | Amass-backed OSINT collector that enriches investigations with external intelligence. |
| `seer` | Passive analytics engine that flags suspicious behavior observed in captured traffic. |
| `scribe` | Reporting pipeline that turns findings into human-friendly Markdown deliverables. |
| `ranker` | Prioritization service that scores leads and findings to focus remediation efforts. |
| `grapher` | Relationship engine that models assets and signals as a navigable graph. |
| `cryptographer` | CyberChef-inspired utility UI for transforming payloads during investigations. |

Refer to each plugin's README for setup guidance and roadmap notes.
