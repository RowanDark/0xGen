package reporter

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/RowanDark/0xgen/internal/findings"
)

const htmlStyles = `:root {
 color-scheme: light dark;
 --bg: #0f172a;
 --surface: #111c34;
 --surface-muted: #1d2a44;
 --border: #1e293b;
 --text: #f8fafc;
 --muted: #94a3b8;
 --accent: #38bdf8;
 --accent-contrast: #0f172a;
 --chip-bg: rgba(148, 163, 184, 0.16);
 --chip-border: rgba(148, 163, 184, 0.35);
 --warn-bg: #b91c1c;
 --warn-text: #fff7ed;
 --crit-bg: #f87171;
 --crit-text: #450a0a;
 --high-bg: #fb923c;
 --high-text: #431407;
 --med-bg: #facc15;
 --med-text: #422006;
 --low-bg: #38bdf8;
 --low-text: #082f49;
 --info-bg: #cbd5f5;
 --info-text: #1f2937;
}

@media (prefers-color-scheme: light) {
 :root {
  --bg: #f8fafc;
  --surface: #ffffff;
  --surface-muted: #f1f5f9;
  --border: #dbe4f3;
  --text: #0f172a;
  --muted: #475569;
  --accent: #2563eb;
  --accent-contrast: #ffffff;
  --chip-bg: rgba(148, 163, 184, 0.18);
  --chip-border: rgba(148, 163, 184, 0.45);
  --warn-bg: #fee2e2;
  --warn-text: #7f1d1d;
  --crit-bg: #b91c1c;
  --crit-text: #fef2f2;
  --high-bg: #c2410c;
  --high-text: #fef3c7;
  --med-bg: #eab308;
  --med-text: #422006;
  --low-bg: #2563eb;
  --low-text: #ffffff;
  --info-bg: #e2e8f0;
  --info-text: #0f172a;
 }
}

* {
 box-sizing: border-box;
}

body {
 margin: 0;
 font-family: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
 background: var(--bg);
 color: var(--text);
 min-height: 100vh;
}

a {
 color: inherit;
}

.header {
 padding: 32px clamp(24px, 6vw, 72px) 16px;
 display: flex;
 flex-direction: column;
 gap: 12px;
 border-bottom: 1px solid var(--border);
 background: radial-gradient(120% 120% at 0% 0%, rgba(56, 189, 248, 0.25), transparent 65%), var(--surface);
}

.header h1 {
 margin: 0;
 font-size: clamp(2rem, 3vw, 2.8rem);
 letter-spacing: -0.015em;
}

.header .meta {
 color: var(--muted);
 font-size: 0.95rem;
}

main {
 padding: 24px clamp(24px, 6vw, 72px) 80px;
 display: flex;
 flex-direction: column;
 gap: 32px;
}

.banner {
 background: var(--warn-bg);
 color: var(--warn-text);
 padding: 16px 24px;
 border-radius: 16px;
 font-weight: 600;
 display: flex;
 gap: 8px;
 align-items: center;
}

.controls {
 display: flex;
 flex-wrap: wrap;
 gap: 16px;
 align-items: center;
 background: var(--surface);
 border: 1px solid var(--border);
 border-radius: 20px;
 padding: 18px 24px;
 box-shadow: 0 20px 45px rgba(15, 23, 42, 0.25);
}

.controls .search {
 flex: 1;
 min-width: 240px;
 display: flex;
 align-items: center;
 gap: 12px;
 background: var(--surface-muted);
 border-radius: 999px;
 padding: 10px 16px;
 border: 1px solid transparent;
}

.controls .search input {
 flex: 1;
 font-size: 1rem;
 border: none;
 background: transparent;
 color: var(--text);
}

.controls .search input:focus {
 outline: none;
}

.controls button {
 border: none;
 border-radius: 999px;
 background: var(--accent);
 color: var(--accent-contrast);
 font-weight: 600;
 padding: 10px 18px;
 cursor: pointer;
 transition: transform 0.2s ease;
}

.controls button:hover {
 transform: translateY(-1px);
}

.severity-chips {
 display: flex;
 gap: 8px;
 flex-wrap: wrap;
 align-items: center;
}

.severity-chip {
 display: inline-flex;
 align-items: center;
 gap: 8px;
 border-radius: 999px;
 padding: 6px 14px;
 font-size: 0.9rem;
 background: var(--chip-bg);
 border: 1px solid var(--chip-border);
 color: var(--muted);
 cursor: pointer;
 transition: opacity 0.2s ease;
}

.severity-chip input {
 display: none;
}

.severity-chip.crit { background: var(--crit-bg); color: var(--crit-text); }
.severity-chip.high { background: var(--high-bg); color: var(--high-text); }
.severity-chip.med { background: var(--med-bg); color: var(--med-text); }
.severity-chip.low { background: var(--low-bg); color: var(--low-text); }
.severity-chip.info { background: var(--info-bg); color: var(--info-text); }

.severity-chip.inactive {
 opacity: 0.35;
}

.stats-grid {
 display: grid;
 gap: 20px;
 grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
}

.stat-card {
 background: var(--surface);
 border: 1px solid var(--border);
 border-radius: 20px;
 padding: 20px 24px;
 box-shadow: 0 20px 45px rgba(15, 23, 42, 0.2);
 display: flex;
 flex-direction: column;
 gap: 6px;
}

.stat-card .label {
 text-transform: uppercase;
 letter-spacing: 0.08em;
 font-size: 0.75rem;
 color: var(--muted);
}

.stat-card .value {
 font-size: 2rem;
 font-weight: 700;
}

.stat-card .hint {
 color: var(--muted);
 font-size: 0.85rem;
}

.panel {
 background: var(--surface);
 border: 1px solid var(--border);
 border-radius: 22px;
 padding: 22px 26px;
 box-shadow: 0 20px 45px rgba(15, 23, 42, 0.2);
}

.panel h2 {
 margin: 0 0 12px 0;
 font-size: 1.4rem;
}

.case-list {
 display: flex;
 flex-direction: column;
 gap: 18px;
}

.case-card {
 border: 1px solid var(--border);
 border-radius: 18px;
 overflow: hidden;
 background: linear-gradient(145deg, rgba(56, 189, 248, 0.18), transparent 60%), var(--surface);
}

.case-card summary {
 list-style: none;
 padding: 18px 22px;
 display: grid;
 grid-template-columns: auto 1fr auto;
 gap: 12px;
 align-items: center;
 cursor: pointer;
}

.case-card summary::-webkit-details-marker {
 display: none;
}

.case-card summary:hover {
 background: rgba(148, 163, 184, 0.12);
}

.case-chip {
 font-weight: 700;
 text-transform: uppercase;
 font-size: 0.75rem;
 letter-spacing: 0.08em;
 padding: 6px 12px;
 border-radius: 999px;
}

.case-card .asset {
 color: var(--muted);
 font-size: 0.9rem;
}

.case-card .body {
 padding: 0 22px 18px 22px;
 display: grid;
 gap: 16px;
}

.case-card dl {
 margin: 0;
 display: grid;
 gap: 4px;
 grid-template-columns: 140px 1fr;
 font-size: 0.95rem;
}

.case-card dl dt {
 color: var(--muted);
}

.case-card dl dd {
 margin: 0;
}

.case-card ul {
 margin: 0;
 padding-left: 18px;
 display: grid;
 gap: 8px;
}

.case-card li {
 line-height: 1.5;
}

.findings-table {
 width: 100%;
 border-collapse: collapse;
 margin-top: 12px;
}

.findings-table th,
.findings-table td {
 text-align: left;
 padding: 10px 14px;
 border-bottom: 1px solid var(--border);
}

.findings-table tbody tr:nth-child(even) {
 background: var(--surface-muted);
}

.badge {
 display: inline-flex;
 align-items: center;
 gap: 6px;
 border-radius: 999px;
 padding: 4px 10px;
 font-size: 0.85rem;
 font-weight: 600;
}

.badge.crit { background: var(--crit-bg); color: var(--crit-text); }
.badge.high { background: var(--high-bg); color: var(--high-text); }
.badge.med { background: var(--med-bg); color: var(--med-text); }
.badge.low { background: var(--low-bg); color: var(--low-text); }
.badge.info { background: var(--info-bg); color: var(--info-text); }

.empty-state {
 text-align: center;
 padding: 40px 0;
 color: var(--muted);
}

@media (max-width: 720px) {
 .case-card summary {
  grid-template-columns: 1fr;
 }
 .case-card dl {
  grid-template-columns: 1fr;
 }
 .case-card dl dt {
  font-weight: 600;
 }
}
`

const htmlAppScript = `(function () {
  const severityOrder = [
    { id: "crit", label: "Critical" },
    { id: "high", label: "High" },
    { id: "med", label: "Medium" },
    { id: "low", label: "Low" },
    { id: "info", label: "Informational" },
  ];

  const state = {
    dataset: null,
    searchQuery: "",
    severities: new Set(severityOrder.map((item) => item.id)),
    filteredCases: [],
  };

  const aliasMap = [
    ["oxg-style", "glyph-style"],
    ["oxg-data", "glyph-data"],
    ["oxg-app", "glyph-app"],
  ];

  document.addEventListener("DOMContentLoaded", init);

  async function init() {
    await verifyIntegrity();
    const dataElement = getElementByIds("oxg-data", "glyph-data");
    if (!dataElement) {
      console.error("dataset element missing");
      return;
    }
    try {
      state.dataset = JSON.parse(dataElement.textContent || "{}");
    } catch (error) {
      console.error("failed to parse dataset", error);
      showIntegrityWarning("dataset parse error");
      return;
    }

    buildSeverityFilters();
    bindControls();
    renderOverview();
    renderFindings();
    applyFilters();
  }

  async function verifyIntegrity() {
    if (!window.crypto || !window.crypto.subtle) {
      return;
    }
    for (const ids of aliasMap) {
      const el = getElementByIds(...ids);
      if (!el) {
        continue;
      }
      const expected = el.getAttribute("data-integrity");
      if (!expected) {
        continue;
      }
      const encoder = new TextEncoder();
      const digest = await window.crypto.subtle.digest(
        "SHA-256",
        encoder.encode(el.textContent || "")
      );
      const actual = "sha256-" + bufferToBase64(digest);
      if (actual !== expected) {
        console.error(
          "integrity mismatch for " +
            (el.id || ids[0]) +
            ": expected " +
            expected +
            ", got " +
            actual,
        );
        showIntegrityWarning(el.id || ids[0]);
        break;
      }
    }
  }

  function getElementByIds(...ids) {
    for (const id of ids) {
      const el = document.getElementById(id);
      if (el) {
        return el;
      }
    }
    return null;
  }

  function showIntegrityWarning(source) {
    const banner = document.getElementById("integrityWarning");
    if (!banner) {
      return;
    }
    banner.hidden = false;
    const code = banner.querySelector("code");
    if (code) {
      code.textContent = source || "unknown";
    }
  }

  function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary);
  }

  function bindControls() {
    const search = document.getElementById("searchInput");
    if (search) {
      search.addEventListener("input", (event) => {
        state.searchQuery = (event.target.value || "").toLowerCase();
        applyFilters();
      });
    }

    const reset = document.getElementById("resetFilters");
    if (reset) {
      reset.addEventListener("click", () => {
        state.searchQuery = "";
        state.severities = new Set(severityOrder.map((item) => item.id));
        if (search) {
          search.value = "";
        }
        updateSeverityChipState();
        applyFilters();
      });
    }
  }

  function buildSeverityFilters() {
    const container = document.getElementById("severityFilters");
    if (!container) {
      return;
    }
    container.innerHTML = "";
    severityOrder.forEach((item) => {
      const label = document.createElement("label");
      label.className = "severity-chip " + item.id;

      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = true;
      checkbox.value = item.id;
      checkbox.addEventListener("change", (event) => {
        if (event.target.checked) {
          state.severities.add(item.id);
        } else {
          state.severities.delete(item.id);
        }
        label.classList.toggle("inactive", !event.target.checked);
        applyFilters();
      });

      const text = document.createElement("span");
      text.textContent = item.label;

      label.append(checkbox, text);
      container.appendChild(label);
    });
  }

  function updateSeverityChipState() {
    const container = document.getElementById("severityFilters");
    if (!container) {
      return;
    }
    const chips = Array.from(container.querySelectorAll("label"));
    chips.forEach((chip) => {
      const checkbox = chip.querySelector("input");
      if (!checkbox) {
        return;
      }
      const value = checkbox.value;
      const checked = state.severities.has(value);
      checkbox.checked = checked;
      chip.classList.toggle("inactive", !checked);
    });
  }

  function applyFilters() {
    const cases = Array.isArray(state.dataset?.cases) ? state.dataset.cases : [];
    const query = state.searchQuery;
    const severities = state.severities;

    const filtered = cases.filter((item) => {
      const severity = normaliseSeverity(item?.risk?.severity);
      if (!severities.has(severity)) {
        return false;
      }
      if (!query) {
        return true;
      }
      return buildSearchText(item).includes(query);
    });

    filtered.sort(compareCases);
    state.filteredCases = filtered;

    renderStats();
    renderCases();
  }

  function compareCases(a, b) {
    const rank = (severity) => {
      const index = severityOrder.findIndex((entry) => entry.id === severity);
      return index === -1 ? Number.MAX_SAFE_INTEGER : index;
    };
    const severityDiff = rank(normaliseSeverity(a?.risk?.severity)) - rank(normaliseSeverity(b?.risk?.severity));
    if (severityDiff !== 0) {
      return severityDiff;
    }
    const timeA = parseTimestamp(b?.generated_at) - parseTimestamp(a?.generated_at);
    if (timeA !== 0) {
      return timeA;
    }
    return (a?.id || "").localeCompare(b?.id || "");
  }

  function buildSearchText(item) {
    const fields = [];
    fields.push(item?.summary || "");
    fields.push(item?.asset?.identifier || "");
    fields.push(item?.asset?.details || "");
    fields.push(item?.vector?.kind || "");
    fields.push(item?.vector?.value || "");
    if (Array.isArray(item?.evidence)) {
      item.evidence.forEach((evidence) => {
        fields.push(evidence?.message || "");
        fields.push(evidence?.evidence || "");
      });
    }
    if (Array.isArray(item?.sources)) {
      item.sources.forEach((src) => {
        fields.push(src?.id || "");
        fields.push(src?.plugin || "");
        fields.push(src?.target || "");
      });
    }
    return fields.join(" ").toLowerCase();
  }

  function renderOverview() {
    const summary = state.dataset?.summary || {};
    setText("generatedAt", formatTimestamp(summary.generated_at || state.dataset?.generated_at));
    if (summary.window_start) {
      setText("windowStart", formatTimestamp(summary.window_start));
    } else {
      setText("windowStart", "All findings");
    }
    setText("windowEnd", formatTimestamp(summary.window_end || summary.generated_at));

    const severityCounts = summary.severity_breakdown || {};
    severityOrder.forEach((entry) => {
      setText("count-" + entry.id, severityCounts[entry.id] ?? 0);
    });

    setText("totalFindings", summary.total ?? state.dataset?.findings_count ?? 0);
    setText("totalCases", Array.isArray(state.dataset?.cases) ? state.dataset.cases.length : 0);

    const sbom = state.dataset?.sbom;
    const sbomSection = document.getElementById("sbomInfo");
    if (sbom && sbomSection) {
      const digest = sbom?.digest?.value
        ? sbom.digest.algorithm + ":" + sbom.digest.value
        : "";
      const pathLabel =
        "<strong>SBOM</strong>: <code>" +
        escapeHTML(sbom.path || "(not provided)") +
        "</code>";
      const digestLabel = digest
        ? " • <code>" + escapeHTML(digest) + "</code>"
        : "";
      sbomSection.innerHTML = pathLabel + digestLabel;
      sbomSection.hidden = false;
    }
  }

  function renderStats() {
    setText("filteredCases", state.filteredCases.length);
    const severityCounts = { crit: 0, high: 0, med: 0, low: 0, info: 0 };
    state.filteredCases.forEach((item) => {
      const severity = normaliseSeverity(item?.risk?.severity);
      if (severityCounts.hasOwnProperty(severity)) {
        severityCounts[severity] += 1;
      }
    });
    Object.entries(severityCounts).forEach(([key, value]) => {
      setText("filtered-" + key, value);
    });
  }

  function renderCases() {
    const container = document.getElementById("caseList");
    if (!container) {
      return;
    }
    container.innerHTML = "";
    if (state.filteredCases.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "No cases match the active filters.";
      container.appendChild(empty);
      return;
    }

    state.filteredCases.forEach((item) => {
      const details = document.createElement("details");
      details.className = "case-card";
      details.open = state.filteredCases.length <= 3;

      const summary = document.createElement("summary");
      const severity = normaliseSeverity(item?.risk?.severity);
      const chip = document.createElement("span");
      chip.className = "case-chip badge " + severity;
      chip.textContent = severityLabel(severity);

      const title = document.createElement("div");
      title.textContent = item?.summary || "Untitled case";

      const asset = document.createElement("div");
      asset.className = "asset";
      asset.textContent = formatAsset(item?.asset);

      summary.append(chip, title, asset);
      details.appendChild(summary);

      const body = document.createElement("div");
      body.className = "body";

      body.appendChild(buildDefinition("Confidence", formatConfidence(item?.confidence)));
      body.appendChild(buildDefinition("Attack vector", formatVector(item?.vector)));
      body.appendChild(buildDefinition("Risk rationale", item?.risk?.rationale || "(not provided)"));

      const evidenceSection = document.createElement("div");
      evidenceSection.innerHTML = "<strong>Evidence</strong>";
      const evidenceList = document.createElement("ul");
      if (Array.isArray(item?.evidence) && item.evidence.length > 0) {
        item.evidence.forEach((evidence) => {
          const li = document.createElement("li");
          const pluginLabel =
            "<strong>" + escapeHTML(evidence?.plugin || "") + "</strong>: ";
          li.innerHTML =
            pluginLabel + escapeHTML(evidence?.message || "(not provided)");
          if (evidence?.evidence) {
            const pre = document.createElement("pre");
            pre.textContent = evidence.evidence;
            pre.style.margin = "6px 0 0 0";
            pre.style.whiteSpace = "pre-wrap";
            li.appendChild(pre);
          }
          evidenceList.appendChild(li);
        });
      } else {
        const li = document.createElement("li");
        li.textContent = "No supporting evidence provided.";
        evidenceList.appendChild(li);
      }
      evidenceSection.appendChild(evidenceList);
      body.appendChild(evidenceSection);

      const sources = Array.isArray(item?.sources) ? item.sources : [];
      if (sources.length > 0) {
        const sourceSection = document.createElement("div");
        sourceSection.innerHTML = "<strong>Source findings</strong>";
        const list = document.createElement("ul");
        sources.forEach((source) => {
          const li = document.createElement("li");
          const anchor = document.createElement("a");
          anchor.href = "#finding-" + (source?.id || "");
          anchor.textContent = source?.id || "unknown";
          li.appendChild(anchor);
          const meta = document.createElement("span");
          meta.textContent =
            " • " +
            (source?.plugin || "") +
            " (" +
            severityLabel(normaliseSeverity(source?.severity)) +
            ")";
          li.appendChild(meta);
          list.appendChild(li);
        });
        sourceSection.appendChild(list);
        body.appendChild(sourceSection);
      }

      details.appendChild(body);
      container.appendChild(details);
    });
  }

  function renderFindings() {
    const table = document.getElementById("findingsTable");
    if (!table) {
      return;
    }
    const findings = Array.isArray(state.dataset?.findings) ? state.dataset.findings : [];
    const tbody = table.querySelector("tbody");
    if (!tbody) {
      return;
    }
    tbody.innerHTML = "";
    findings
      .slice()
      .sort((a, b) => parseTimestamp(b?.ts) - parseTimestamp(a?.ts))
      .forEach((finding) => {
        const row = document.createElement("tr");
        row.id = "finding-" + (finding?.id || "");

        const severityCell = document.createElement("td");
        const badge = document.createElement("span");
        const severity = normaliseSeverity(finding?.severity);
        badge.className = "badge " + severity;
        badge.textContent = severityLabel(severity);
        severityCell.appendChild(badge);

        const pluginCell = document.createElement("td");
        pluginCell.textContent = finding?.plugin || "";

        const targetCell = document.createElement("td");
        targetCell.textContent = finding?.target || "(not specified)";

        const messageCell = document.createElement("td");
        messageCell.textContent = finding?.message || "(not provided)";

        const timeCell = document.createElement("td");
        timeCell.textContent = formatTimestamp(finding?.ts);

        row.append(severityCell, pluginCell, targetCell, messageCell, timeCell);
        tbody.appendChild(row);
      });
  }

  function buildDefinition(label, value) {
    const wrapper = document.createElement("dl");
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    wrapper.append(dt, dd);
    return wrapper;
  }

  function formatConfidence(value) {
    if (typeof value === "number" && !Number.isNaN(value)) {
      return Math.round(value * 100) + "%";
    }
    return "(not scored)";
  }

  function formatAsset(asset) {
    if (!asset) {
      return "Unknown asset";
    }
    const kind = asset?.kind || "asset";
    const identifier = asset?.identifier || "(not specified)";
    return kind.toUpperCase() + " • " + identifier;
  }

  function formatVector(vector) {
    if (!vector) {
      return "(not provided)";
    }
    if (vector?.value) {
      return (vector.kind || "") + " → " + vector.value;
    }
    return vector?.kind || "(not provided)";
  }

  function parseTimestamp(input) {
    if (!input) {
      return 0;
    }
    const time = Date.parse(input);
    return Number.isNaN(time) ? 0 : time;
  }

  function formatTimestamp(input) {
    if (!input) {
      return "(unknown)";
    }
    const time = new Date(input);
    if (Number.isNaN(time.getTime())) {
      return input;
    }
    return time.toISOString().replace("T", " ").replace("Z", " UTC");
  }

  function severityLabel(input) {
    const entry = severityOrder.find((item) => item.id === input);
    return entry ? entry.label : input;
  }

  function normaliseSeverity(input) {
    if (typeof input !== "string") {
      return "info";
    }
    const value = input.toLowerCase().trim();
    if (["crit", "critical"].includes(value)) return "crit";
    if (["high"].includes(value)) return "high";
    if (["med", "medium"].includes(value)) return "med";
    if (["low"].includes(value)) return "low";
    return "info";
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = value == null ? "" : String(value);
    }
  }

  function escapeHTML(value) {
    return (value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
})();
`

// RenderHTML produces an interactive HTML report backed by the case bundle dataset.
func RenderHTML(list []findings.Finding, opts ReportOptions) (string, error) {
	bundle, err := BuildBundle(opts.Context, list, opts)
	if err != nil {
		return "", err
	}

	dataset, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode dataset: %w", err)
	}

	dataset = append(dataset, '\n')
	datasetEscaped := escapeScriptContent(string(dataset))

	styleDigest := sha256Base64([]byte(htmlStyles))
	scriptDigest := sha256Base64([]byte(htmlAppScript))
	dataDigest := sha256Base64([]byte(datasetEscaped))

	var b strings.Builder
	b.WriteString("<!doctype html>\n")
	b.WriteString("<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>0xgen Findings Report</title>\n")
	b.WriteString(fmt.Sprintf("<style id=\"oxg-style\" data-integrity=\"sha256-%s\">\n%s\n</style>\n", styleDigest, htmlStyles))
	b.WriteString("</head>\n<body>\n")
	b.WriteString("<header class=\"header\">\n<h1>0xgen Findings Report</h1>\n<p class=\"meta\">Generated at <span id=\"generatedAt\">(pending)</span></p>\n<div class=\"meta\">Window: <span id=\"windowStart\">(pending)</span> → <span id=\"windowEnd\">(pending)</span></div>\n</header>\n")
	b.WriteString("<main id=\"oxg-report-root\">\n<div id=\"integrityWarning\" class=\"banner\" hidden>Integrity check failed for <code>unknown</code>. Refresh or regenerate this report to continue.</div>\n")
	b.WriteString("<section class=\"controls\">\n<div class=\"search\"><input id=\"searchInput\" type=\"search\" placeholder=\"Search findings, assets, or evidence\" aria-label=\"Search\"></div>\n<div class=\"severity-chips\" id=\"severityFilters\"></div>\n<button type=\"button\" id=\"resetFilters\">Reset filters</button>\n</section>\n")
	b.WriteString("<section class=\"stats-grid\">\n<div class=\"stat-card\"><span class=\"label\">Cases in view</span><span class=\"value\" id=\"filteredCases\">0</span><span class=\"hint\">of <span id=\"totalCases\">0</span> total</span></div>\n<div class=\"stat-card\"><span class=\"label\">Findings analysed</span><span class=\"value\" id=\"totalFindings\">0</span><span class=\"hint\" id=\"sbomInfo\" hidden></span></div>\n<div class=\"stat-card\"><span class=\"label\">Critical / High / Medium</span><span class=\"value\"><span id=\"filtered-crit\">0</span> / <span id=\"filtered-high\">0</span> / <span id=\"filtered-med\">0</span></span><span class=\"hint\">Low <span id=\"filtered-low\">0</span> • Informational <span id=\"filtered-info\">0</span></span></div>\n</section>\n")
	b.WriteString("<section class=\"panel\">\n<h2>Cases</h2>\n<div class=\"case-list\" id=\"caseList\"></div>\n</section>\n")
	b.WriteString("<section class=\"panel\">\n<h2>Source Findings</h2>\n<table class=\"findings-table\" id=\"findingsTable\"><thead><tr><th>Severity</th><th>Plugin</th><th>Target</th><th>Message</th><th>Detected</th></tr></thead><tbody></tbody></table>\n</section>\n</main>\n<div id=\"glyph-report-root\" style=\"display:none\"></div>\n")
	b.WriteString(fmt.Sprintf("<script type=\"application/json\" id=\"oxg-data\" data-integrity=\"sha256-%s\">%s</script>\n", dataDigest, datasetEscaped))
	b.WriteString(fmt.Sprintf("<script id=\"oxg-app\" data-integrity=\"sha256-%s\">\n%s\n</script>\n", scriptDigest, htmlAppScript))
	b.WriteString("</body>\n</html>\n")

	return b.String(), nil
}

func sha256Base64(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}

var scriptCloseTagPattern = regexp.MustCompile(`(?i)</script`)

func escapeScriptContent(input string) string {
	// Prevent </script> (in any casing) from terminating the element prematurely.
	return scriptCloseTagPattern.ReplaceAllStringFunc(input, func(match string) string {
		return "<\\/" + match[2:]
	})
}
