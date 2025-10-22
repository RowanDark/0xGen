const severityOrder = [
  { id: "crit", label: "Critical" },
  { id: "high", label: "High" },
  { id: "med", label: "Medium" },
  { id: "low", label: "Low" },
  { id: "info", label: "Informational" },
];

const severityRank = severityOrder.reduce((acc, item, index) => {
  acc[item.id] = index;
  return acc;
}, {});

const state = {
  allCases: [],
  filteredCases: [],
  telemetry: null,
  findingsCount: 0,
  refreshedAt: "",
  searchQuery: "",
  severities: new Set(severityOrder.map((item) => item.id)),
};

async function init() {
  buildSeverityFilters();
  bindControls();
  try {
    const data = await fetchDataset();
    state.allCases = Array.isArray(data.cases) ? data.cases : [];
    state.telemetry = data.telemetry || null;
    state.findingsCount = typeof data.findings_count === "number" ? data.findings_count : 0;
    state.refreshedAt = typeof data.refreshed_at === "string" ? data.refreshed_at : "";
    hideError();
  } catch (error) {
    console.error("Failed to load dataset", error);
    showError();
    return;
  }

  applyFilters();
}

document.addEventListener("DOMContentLoaded", init);

function bindControls() {
  const searchInput = document.getElementById("searchInput");
  if (searchInput) {
    searchInput.addEventListener("input", (event) => {
      state.searchQuery = event.target.value || "";
      applyFilters();
    });
  }

  const resetButton = document.getElementById("resetFilters");
  if (resetButton) {
    resetButton.addEventListener("click", () => {
      state.searchQuery = "";
      state.severities = new Set(severityOrder.map((item) => item.id));
      updateSeverityChipState();
      if (searchInput) {
        searchInput.value = "";
      }
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
    label.className = `severity-chip severity-${item.id}`;

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = item.id;
    checkbox.checked = true;
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
  const chips = Array.from(container.querySelectorAll("label.severity-chip"));
  chips.forEach((chip) => {
    const checkbox = chip.querySelector("input[type='checkbox']");
    if (!checkbox) {
      return;
    }
    const value = checkbox.value;
    const checked = state.severities.has(value);
    checkbox.checked = checked;
    chip.classList.toggle("inactive", !checked);
  });
}

async function fetchDataset() {
  const response = await fetch("/api/data", { headers: { "Accept": "application/json" } });
  if (!response.ok) {
    throw new Error(`unexpected status ${response.status}`);
  }
  return response.json();
}

function applyFilters() {
  const query = state.searchQuery.trim().toLowerCase();
  const severities = state.severities;

  const filtered = state.allCases.filter((caze) => {
    const severity = normaliseSeverity(caze?.risk?.severity);
    if (!severities.has(severity)) {
      return false;
    }
    if (!query) {
      return true;
    }
    return buildSearchText(caze).includes(query);
  });

  filtered.sort(compareCases);
  state.filteredCases = filtered;

  renderStats();
  renderCases();
}

function compareCases(a, b) {
  const severityA = severityRank[normaliseSeverity(a?.risk?.severity)] ?? Number.MAX_SAFE_INTEGER;
  const severityB = severityRank[normaliseSeverity(b?.risk?.severity)] ?? Number.MAX_SAFE_INTEGER;
  if (severityA !== severityB) {
    return severityA - severityB;
  }
  const timeA = parseTime(b?.generated_at) - parseTime(a?.generated_at);
  if (timeA !== 0) {
    return timeA;
  }
  return (a?.id || "").localeCompare(b?.id || "");
}

function parseTime(value) {
  if (!value) {
    return 0;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return 0;
  }
  return parsed.getTime();
}

function renderStats() {
  const caseCount = document.getElementById("caseCount");
  const findingCount = document.getElementById("findingCount");
  const updatedAt = document.getElementById("updatedAt");
  const severityBreakdown = document.getElementById("severityBreakdown");

  if (caseCount) {
    const total = state.allCases.length;
    const visible = state.filteredCases.length;
    caseCount.textContent = total > 0 ? `${visible} / ${total}` : "0";
  }
  if (findingCount) {
    findingCount.textContent = state.findingsCount.toString();
  }
  if (updatedAt) {
    updatedAt.textContent = formatDate(state.refreshedAt);
  }
  if (severityBreakdown) {
    severityBreakdown.innerHTML = "";
    const counts = (state.telemetry && state.telemetry.severity_counts) || {};
    severityOrder.forEach((item) => {
      const pill = document.createElement("span");
      pill.className = `severity-pill severity-${item.id}`;
      const total = counts[item.id] ?? 0;
      const visible = state.filteredCases.filter(
        (caze) => normaliseSeverity(caze?.risk?.severity) === item.id,
      ).length;
      pill.textContent = `${item.label}: ${total}${visible !== total ? ` (showing ${visible})` : ""}`;
      severityBreakdown.appendChild(pill);
    });
  }
}

function renderCases() {
  const container = document.getElementById("caseList");
  const emptyState = document.getElementById("emptyState");
  if (!container) {
    return;
  }
  container.innerHTML = "";
  if (state.filteredCases.length === 0) {
    if (emptyState) {
      const heading = emptyState.querySelector("h2");
      const description = emptyState.querySelector("p");
      if (heading) {
        heading.textContent = state.allCases.length === 0 ? "No cases available" : "No cases match your filters";
      }
      if (description) {
        description.textContent =
          state.allCases.length === 0
            ? "Run a scan or export findings to generate Case data, then refresh this view."
            : "Adjust the severity filters or search query to see more results.";
      }
      emptyState.classList.remove("hidden");
    }
    return;
  }
  if (emptyState) {
    emptyState.classList.add("hidden");
  }
  state.filteredCases.forEach((caze) => {
    const card = document.createElement("details");
    card.className = "case-card";

    const summary = document.createElement("summary");
    summary.className = "case-summary";

    const header = document.createElement("div");
    header.className = "case-header";

    const severityCode = normaliseSeverity(caze?.risk?.severity);
    const badge = createSeverityBadge(severityCode);
    header.appendChild(badge);

    const title = document.createElement("span");
    title.className = "case-title";
    title.textContent = normaliseText(caze.summary) || "Untitled case";
    header.appendChild(title);

    summary.appendChild(header);

    const meta = document.createElement("span");
    meta.className = "case-meta";
    const parts = [formatAssetShort(caze.asset), formatVector(caze.vector), caze.id];
    meta.textContent = parts.filter(Boolean).join(" • ");
    summary.appendChild(meta);

    card.appendChild(summary);

    const body = document.createElement("div");
    body.className = "case-body";

    const overview = buildOverviewSection(caze);
    body.appendChild(overview);

    const summarySection = buildSummarySection(caze.summary);
    if (summarySection) {
      body.appendChild(summarySection);
    }

    const proofSection = buildProofSection(caze.proof);
    if (proofSection) {
      body.appendChild(proofSection);
    }

    const evidenceSection = buildEvidenceSection(caze.evidence);
    if (evidenceSection) {
      body.appendChild(evidenceSection);
    }

    const sourcesSection = buildSourcesSection(caze.sources);
    if (sourcesSection) {
      body.appendChild(sourcesSection);
    }

    const graphSection = buildGraphSection(caze.graph);
    if (graphSection) {
      body.appendChild(graphSection);
    }

    const downloads = buildDownloadsSection(caze.id);
    body.appendChild(downloads);

    card.appendChild(body);
    container.appendChild(card);
  });
}

function buildOverviewSection(caze) {
  const section = createSection("Overview");
  const list = document.createElement("dl");
  list.className = "case-details";

  addDefinition(list, "Case ID", caze.id || "–");
  addDefinition(list, "Asset", formatAsset(caze.asset));
  addDefinition(list, "Attack vector", formatVector(caze.vector) || "–");

  const riskScore = typeof caze?.risk?.score === "number" ? caze.risk.score.toFixed(1) : "–";
  addDefinition(list, "Risk score", riskScore);

  const confidence = typeof caze?.confidence === "number" ? caze.confidence.toFixed(2) : "–";
  addDefinition(list, "Confidence", confidence);

  addDefinition(list, "Generated", formatDate(caze?.generated_at));

  if (caze?.confidence_log) {
    addDefinition(list, "Confidence log", caze.confidence_log);
  }

  const labels = normaliseLabels(caze.labels);
  if (labels.length > 0) {
    const container = document.createElement("div");
    container.className = "metadata-list";
    labels.forEach((label) => {
      const item = document.createElement("span");
      item.className = "metadata-item";
      item.textContent = label;
      container.appendChild(item);
    });
    addDefinition(list, "Labels", container);
  }

  section.appendChild(list);
  return section;
}

function buildSummarySection(summaryText) {
  const normalised = normaliseText(summaryText);
  if (!normalised) {
    return null;
  }
  const section = createSection("Summary");
  section.appendChild(buildParagraphs(normalised));
  return section;
}

function buildProofSection(proof) {
  if (!proof || (!normaliseText(proof.summary) && !Array.isArray(proof.steps))) {
    return null;
  }
  const section = createSection("Proof of concept");
  if (normaliseText(proof.summary)) {
    section.appendChild(buildParagraphs(proof.summary));
  }
  if (Array.isArray(proof.steps) && proof.steps.length > 0) {
    const list = document.createElement("ol");
    list.className = "proof-steps";
    proof.steps
      .map((step) => normaliseText(step))
      .filter(Boolean)
      .forEach((step) => {
        const item = document.createElement("li");
        item.textContent = step;
        list.appendChild(item);
      });
    if (list.childNodes.length > 0) {
      section.appendChild(list);
    }
  }
  if (section.childNodes.length === 0) {
    const para = document.createElement("p");
    para.textContent = "No proof of concept steps were provided.";
    section.appendChild(para);
  }
  return section;
}

function buildEvidenceSection(evidence) {
  if (!Array.isArray(evidence) || evidence.length === 0) {
    return null;
  }
  const section = createSection("Evidence");
  const grid = document.createElement("div");
  grid.className = "evidence-grid";

  evidence.forEach((item, index) => {
    const card = document.createElement("article");
    card.className = "evidence-card";

    const header = document.createElement("header");
    const title = document.createElement("strong");
    const plugin = normaliseText(item?.plugin) || "Unknown plugin";
    const type = normaliseText(item?.type) || "evidence";
    title.textContent = `${plugin} • ${type}`;
    header.appendChild(title);

    const counter = document.createElement("span");
    counter.className = "case-meta";
    counter.textContent = `#${index + 1}`;
    header.appendChild(counter);

    card.appendChild(header);

    if (normaliseText(item?.message)) {
      const message = document.createElement("p");
      message.textContent = item.message.trim();
      card.appendChild(message);
    }

    if (normaliseText(item?.evidence)) {
      const blob = document.createElement("pre");
      blob.className = "graph-code";
      blob.textContent = item.evidence.trim();
      card.appendChild(blob);
    }

    const metadataEntries = normaliseMetadata(item?.metadata);
    if (metadataEntries.length > 0) {
      const metaContainer = document.createElement("div");
      metaContainer.className = "metadata-list";
      metadataEntries.forEach((entry) => {
        const pill = document.createElement("span");
        pill.className = "metadata-item";
        pill.textContent = `${entry.key}: ${entry.value}`;
        metaContainer.appendChild(pill);
      });
      card.appendChild(metaContainer);
    }

    grid.appendChild(card);
  });

  section.appendChild(grid);
  return section;
}

function buildSourcesSection(sources) {
  if (!Array.isArray(sources) || sources.length === 0) {
    return null;
  }
  const section = createSection("Source findings");
  const list = document.createElement("ul");
  list.className = "sources-list";

  sources.forEach((source) => {
    const item = document.createElement("li");
    const line = [];
    if (source?.plugin) {
      line.push(source.plugin);
    }
    if (source?.type) {
      line.push(source.type);
    }
    if (source?.target) {
      line.push(source.target);
    }
    if (source?.id) {
      line.push(`ID: ${source.id}`);
    }
    const text = line.filter(Boolean).join(" • ");
    item.textContent = text || "Source";

    const severityCode = normaliseSeverity(source?.severity);
    const badge = createSeverityBadge(severityCode);
    item.prepend(badge);

    list.appendChild(item);
  });

  section.appendChild(list);
  return section;
}

function buildGraphSection(graph) {
  if (!graph) {
    return null;
  }
  const section = createSection("Attack path");
  if (normaliseText(graph.summary)) {
    section.appendChild(buildParagraphs(graph.summary));
  }

  if (Array.isArray(graph.attack_path) && graph.attack_path.length > 0) {
    const chain = document.createElement("ol");
    chain.className = "chain-list";
    graph.attack_path.forEach((step) => {
      const item = document.createElement("li");
      item.className = "chain-step";

      const stage = document.createElement("div");
      stage.className = "stage";
      const stageLabel = typeof step?.stage === "number" ? `Stage ${step.stage}` : "Stage";
      stage.textContent = stageLabel;
      item.appendChild(stage);

      if (normaliseText(step?.description)) {
        const description = document.createElement("div");
        description.textContent = step.description.trim();
        item.appendChild(description);
      }

      const flow = document.createElement("div");
      flow.className = "flow";
      const from = normaliseText(step?.from) || "origin";
      const to = normaliseText(step?.to) || "target";
      flow.textContent = `${from} → ${to}`;
      item.appendChild(flow);

      const meta = document.createElement("div");
      meta.className = "case-meta";
      const parts = [];
      if (step?.plugin) {
        parts.push(step.plugin);
      }
      if (step?.type) {
        parts.push(step.type);
      }
      if (step?.finding_id) {
        parts.push(`Finding ${step.finding_id}`);
      }
      meta.textContent = parts.join(" • ");
      const badge = createSeverityBadge(normaliseSeverity(step?.severity));
      meta.appendChild(badge);
      item.appendChild(meta);

      if (step?.weak_link) {
        const weak = document.createElement("div");
        weak.className = "case-meta";
        weak.textContent = "Weak link";
        item.appendChild(weak);
      }

      chain.appendChild(item);
    });
    section.appendChild(chain);
  }

  if (normaliseText(graph.mermaid)) {
    const raw = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "View Mermaid definition";
    raw.appendChild(summary);
    const pre = document.createElement("pre");
    pre.className = "graph-code";
    pre.textContent = graph.mermaid.trim();
    raw.appendChild(pre);
    section.appendChild(raw);
  }

  return section.childNodes.length === 0 ? null : section;
}

function buildDownloadsSection(caseID) {
  const section = createSection("Downloads");
  const container = document.createElement("div");
  container.className = "case-downloads";

  const jsonLink = createDownloadLink(`/download/case/${encodeURIComponent(caseID)}.json`, "Case JSON");
  const markdownLink = createDownloadLink(`/download/case/${encodeURIComponent(caseID)}.md`, "Case Markdown");
  const pocLink = createDownloadLink(`/download/case/${encodeURIComponent(caseID)}/poc.txt`, "POC steps");

  container.append(jsonLink, markdownLink, pocLink);
  section.appendChild(container);
  return section;
}

function createDownloadLink(href, label) {
  const link = document.createElement("a");
  link.href = href;
  link.textContent = label;
  link.setAttribute("download", "");
  return link;
}

function createSection(title) {
  const section = document.createElement("section");
  section.className = "case-section";
  const heading = document.createElement("h3");
  heading.textContent = title;
  section.appendChild(heading);
  return section;
}

function addDefinition(list, label, value) {
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  if (value instanceof Node) {
    dd.appendChild(value);
  } else {
    dd.textContent = value || "–";
  }
  list.append(dt, dd);
}

function buildParagraphs(text) {
  const fragment = document.createDocumentFragment();
  text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      const p = document.createElement("p");
      p.textContent = line;
      fragment.appendChild(p);
    });
  if (!fragment.childNodes.length) {
    const p = document.createElement("p");
    p.textContent = text;
    fragment.appendChild(p);
  }
  return fragment;
}

function normaliseMetadata(metadata) {
  if (!metadata || typeof metadata !== "object") {
    return [];
  }
  return Object.keys(metadata)
    .filter((key) => normaliseText(metadata[key]))
    .sort()
    .map((key) => ({ key, value: metadata[key] }));
}

function normaliseLabels(labels) {
  if (!labels || typeof labels !== "object") {
    return [];
  }
  return Object.keys(labels)
    .sort()
    .map((key) => `${key}: ${labels[key]}`);
}

function normaliseText(value) {
  if (typeof value !== "string") {
    return "";
  }
  return value.trim();
}

function normaliseSeverity(value) {
  if (typeof value !== "string") {
    return "info";
  }
  const lower = value.toLowerCase();
  return severityOrder.some((item) => item.id === lower) ? lower : "info";
}

function createSeverityBadge(code) {
  const badge = document.createElement("span");
  badge.className = `severity-badge severity-${code}`;
  badge.textContent = severityOrder.find((item) => item.id === code)?.label || code;
  return badge;
}

function formatAsset(asset) {
  if (!asset) {
    return "Unknown";
  }
  const identifier = normaliseText(asset.identifier);
  const kind = normaliseText(asset.kind);
  if (identifier && kind) {
    return `${identifier} (${kind})`;
  }
  return identifier || kind || "Unknown";
}

function formatAssetShort(asset) {
  if (!asset) {
    return "";
  }
  const identifier = normaliseText(asset.identifier);
  if (identifier) {
    return identifier;
  }
  return normaliseText(asset.kind);
}

function formatVector(vector) {
  if (!vector) {
    return "";
  }
  const kind = normaliseText(vector.kind);
  const value = normaliseText(vector.value);
  if (kind && value) {
    return `${kind} (${value})`;
  }
  return kind || value || "";
}

function formatDate(value) {
  if (!value) {
    return "–";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function buildSearchText(caze) {
  const bits = [];
  bits.push(caze?.id);
  bits.push(caze?.summary);
  bits.push(caze?.proof?.summary);
  bits.push(caze?.graph?.summary);
  bits.push(caze?.asset?.identifier);
  bits.push(caze?.asset?.kind);
  bits.push(caze?.vector?.kind);
  bits.push(caze?.vector?.value);
  if (Array.isArray(caze?.evidence)) {
    caze.evidence.forEach((item) => {
      bits.push(item?.plugin);
      bits.push(item?.type);
      bits.push(item?.message);
      bits.push(item?.evidence);
    });
  }
  if (Array.isArray(caze?.sources)) {
    caze.sources.forEach((source) => {
      bits.push(source?.plugin);
      bits.push(source?.type);
      bits.push(source?.target);
      bits.push(source?.id);
    });
  }
  return bits
    .filter((value) => typeof value === "string" && value.trim().length > 0)
    .join(" ")
    .toLowerCase();
}

function showError() {
  const banner = document.getElementById("errorBanner");
  const stats = document.getElementById("statsPanel");
  const caseList = document.getElementById("caseList");
  if (banner) {
    banner.classList.remove("hidden");
  }
  if (stats) {
    stats.classList.add("hidden");
  }
  if (caseList) {
    caseList.innerHTML = "";
  }
}

function hideError() {
  const banner = document.getElementById("errorBanner");
  const stats = document.getElementById("statsPanel");
  if (banner) {
    banner.classList.add("hidden");
  }
  if (stats) {
    stats.classList.remove("hidden");
  }
}
