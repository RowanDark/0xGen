# Plugin installation wizard

Glyph's plugin installer now walks operators through a least-privilege review before a
binary is allowed to run. The wizard renders the manifest metadata, explains every
requested capability in plain language, and makes it easy to deny unnecessary access or
audit grants later. This page documents the experience so security reviewers and support
teams can validate the flow end-to-end.

## Step 1 – Manifest & signature review {#manifest-review}

1. Upload the plugin bundle or point the wizard at a registry URL. Glyph extracts the
   embedded `manifest.json` and verifies the detached signature exactly as described in
   the [plugin marketplace](catalog.md) pipeline.
2. The first screen shows the plugin name, publisher, version, and hashes alongside the
   manifest capabilities. Each capability is paired with a short human-readable summary
   describing what the plugin can touch (for example, *"CAP_HTTP_ACTIVE – allows outbound
   HTTP requests through the Glyph netgate"*).
3. Operators must acknowledge the capability list before continuing. Warnings are raised
   automatically when the manifest requests high-risk scopes such as raw flow access or
   storage privileges.

## Step 2 – Capability risk deep dive {#capability-risk}

The second step expands each capability into the risks and mitigations Glyph enforces:

- **Network helpers (`CAP_HTTP_ACTIVE`, `CAP_WS`)** – emphasise that these capabilities
  allow active scanning and require explicit scoping in run configurations. The wizard
  links to any existing allowlists so reviewers know which domains would be reachable.
- **Data export (`CAP_STORAGE`, `CAP_REPORT`)** – highlight that findings or artefacts can
  leave the sandbox and should only be granted to trusted publishers. Operators can deny
  the capability here, forcing the plugin to rely on default storage-less behaviour.
- **Flow inspection (`CAP_FLOW_INSPECT`, `CAP_FLOW_INSPECT_RAW`)** – explain the
  difference between sanitized and raw streams. Denying the raw capability keeps secrets
  redacted even if the sanitized stream remains enabled.
- **Findings emission (`CAP_EMIT_FINDINGS`)** – stress that revoking this prevents the
  plugin from contributing to case data at all. The wizard flags the capability as a
  prerequisite for most analytical plugins so reviewers can make an informed trade-off.

Capabilities disabled in this step are omitted from the runtime grant request. Glyph's
netgate verifies the final capability list when the plugin starts; missing permissions
result in immediate runtime denials so no unintended data is exposed.【F:internal/netgate/gate.go†L319-L402】

## Step 3 – Redaction and secret access matrix {#redaction-matrix}

After selecting capabilities the wizard renders a data access matrix that mirrors Glyph's
runtime redaction rules:

| Data source | Sanitized view | Raw view | Capability toggle |
| ----------- | -------------- | -------- | ----------------- |
| HTTP request bodies | Secrets are replaced with `[REDACTED …]` placeholders; headers like `Authorization` are scrubbed. | Original payload with length/digest metadata; subject to the global body size limit. | `CAP_FLOW_INSPECT` for sanitized, `CAP_FLOW_INSPECT_RAW` for raw. |
| Findings history | Read-only access to past findings for correlation. | Export and mutation via reporting helpers. | `CAP_EMIT_FINDINGS` (view), `CAP_REPORT` (export). |
| Storage buckets | No access. | Read/write to managed artefact buckets. | `CAP_STORAGE`. |
| HTTP egress | Blocked entirely. | Outbound requests proxied through Glyph with full observability. | `CAP_HTTP_ACTIVE` / `CAP_WS`. |

Reviewers can adjust the toggles directly in the matrix. Revoking a capability updates
the summary pane instantly and ensures the runtime never hands out access the reviewer
rejected.

## Step 4 – Grant summary & audit logging {#audit}

The final screen confirms the selected capability set and creates an immutable audit log
entry once the operator clicks **Install**. Audit events reuse the structured logging
already emitted by the gate layer (`glyph.audit.capability_grant` for approvals and
`glyph.audit.capability_denied` when a plugin later attempts to exceed its grant).【F:internal/logging/audit.go†L20-L21】【F:internal/netgate/gate.go†L448-L468】

From the summary screen operators can jump directly to the **Manage grants** panel for
already-installed plugins. The panel lists:

- Granted capabilities with the approving user, timestamp, and linked audit event.
- Quick revoke toggles that immediately call the gate's `Unregister` path, stripping the
  capability without restarting the plugin.【F:internal/netgate/gate.go†L319-L354】
- A download button that exports the audit history for offline reviews.

## Runtime behaviour & acceptance criteria {#runtime}

These UX improvements pair with existing runtime guardrails:

- Plugins launched without a granted capability receive deterministic errors when they
  request the restricted helper. The gate refuses the operation and emits a
  `capability_denied` audit entry so teams can trace misconfigurations.【F:internal/netgate/gate.go†L390-L452】
- Revoking a capability via the management panel takes effect immediately because the
  gate stops advertising the capability as soon as `Unregister` runs. Subsequent attempts
  to use the helper fail and are logged just like initial denials.【F:internal/netgate/gate.go†L345-L452】

Operators can therefore trust that the installer exposes requested powers up front, that
redaction rules stay enforced unless raw access is explicitly granted, and that every
change is captured in the audit log for future forensics.
