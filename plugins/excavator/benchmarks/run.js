#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');

const { crawlSite } = require('../crawl');

const DEFAULT_ITERATIONS = Number.parseInt(process.env.EXCAVATOR_BENCH_ITERATIONS, 10) || 5;
const DEFAULT_BUDGET = Number.parseFloat(process.env.EXCAVATOR_BENCH_BUDGET || '') || 10;
const MEMORY_SAMPLE_INTERVAL_MS = 10;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const scenarioPath = args.scenarios || path.join(__dirname, 'scenarios.json');
  const scenarios = loadScenarios(scenarioPath);
  if (scenarios.length === 0) {
    throw new Error(`no scenarios defined in ${scenarioPath}`);
  }

  const iterations = args.iterations || DEFAULT_ITERATIONS;
  const budget = args.budget ?? DEFAULT_BUDGET;
  const summaries = [];

  for (const scenario of scenarios) {
    const summary = await executeScenario(scenario, iterations);
    summaries.push(summary);
  }

  const results = {
    generatedAt: new Date().toISOString(),
    iterations,
    scenarios: summaries,
  };

  const baselinePath = args.baseline;
  let baseline;
  if (baselinePath) {
    baseline = loadBaseline(baselinePath);
  }

  const comparison = baseline ? compareAgainstBaseline(summaries, baseline, budget) : null;

  if (baseline && args.updateBaseline) {
    const baselinePayload = buildBaselinePayload(summaries);
    fs.writeFileSync(baselinePath, `${JSON.stringify(baselinePayload, null, 2)}\n`, 'utf8');
  }

  if (args.json) {
    const jsonPath = path.resolve(args.json);
    fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
    fs.writeFileSync(jsonPath, `${JSON.stringify(results, null, 2)}\n`, 'utf8');
  }

  const markdown = renderMarkdown(results, comparison, baseline, budget);
  if (args.summary) {
    fs.mkdirSync(path.dirname(args.summary), { recursive: true });
    fs.writeFileSync(args.summary, `${markdown}\n`, 'utf8');
  }

  if (process.env.GITHUB_STEP_SUMMARY) {
    try {
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdown}\n`, 'utf8');
    } catch (error) {
      console.warn('failed to write GitHub summary:', error.message || error);
    }
  }

  if (comparison && comparison.failures.length > 0) {
    console.error('\nRegression budget exceeded:');
    for (const failure of comparison.failures) {
      console.error(
        `  - ${failure.scenario}: ${failure.metric} dropped ${formatNumber(failure.deltaPercent, 2)}% (baseline ${formatNumber(
          failure.baselineValue,
          2
        )}, current ${formatNumber(failure.currentValue, 2)})`
      );
    }
    process.exitCode = 2;
  }

  process.stdout.write(`${markdown}\n`);
}

async function executeScenario(config, iterations) {
  const runs = [];
  for (let i = 0; i < iterations; i += 1) {
    const run = await runBenchmarkIteration(config, i + 1);
    runs.push(run);
  }

  return summariseScenario(config, runs);
}

async function runBenchmarkIteration(config, iteration) {
  const target = new SyntheticTarget(config);
  const stats = {
    attempted: 0,
    succeeded: 0,
    throttled: 0,
  };

  const fetchPage = async (url) => {
    stats.attempted += 1;
    const { status, links, scripts } = await target.fetch(url, stats.attempted);
    if (status >= 400 && status < 500) {
      if (status === target.throttleStatus) {
        stats.throttled += 1;
      }
    } else {
      stats.succeeded += 1;
    }
    return { url, status, links, scripts };
  };

  const cpuStart = process.cpuUsage();
  const start = performance.now();
  const { result, peak } = await trackMemory(async () => {
    return crawlSite({
      seed: target.seed,
      depth: target.depth,
      hostLimit: 1,
      fetchPage,
      delayMs: target.delayMs,
      maxPages: target.totalPages,
      scope: 'origin',
      scopeAllowlist: [{ type: 'domain', value: target.host }],
      now: () => new Date(),
    });
  });
  const elapsedMs = performance.now() - start;
  const cpuUsage = process.cpuUsage(cpuStart);
  const cpuMs = (cpuUsage.user + cpuUsage.system) / 1000;
  const cpuPercent = elapsedMs > 0 ? (cpuMs / elapsedMs) * 100 : 0;

  const urlsPerMinute = elapsedMs > 0 ? (stats.succeeded / elapsedMs) * 60000 : 0;
  const banRate = stats.attempted > 0 ? stats.throttled / stats.attempted : 0;

  return {
    iteration,
    elapsedMs,
    urlsPerMinute,
    visitedUrls: stats.succeeded,
    attemptedRequests: stats.attempted,
    throttledResponses: stats.throttled,
    banRate,
    memoryPeakBytes: peak,
    cpuPercent,
    result,
  };
}

class SyntheticTarget {
  constructor(config) {
    if (!config || typeof config !== 'object') {
      throw new Error('scenario configuration must be an object');
    }
    if (typeof config.seed !== 'string' || !config.seed.startsWith('http')) {
      throw new Error('scenario seed must be an absolute URL');
    }
    this.name = config.name || 'unnamed';
    this.description = config.description || '';
    this.seed = config.seed;
    this.depth = Number.isFinite(config.depth) && config.depth >= 0 ? Math.floor(config.depth) : 0;
    this.branching = Number.isFinite(config.branching) && config.branching > 0 ? Math.floor(config.branching) : 0;
    this.delayMs = Number.isFinite(config.delayMs) && config.delayMs > 0 ? Math.floor(config.delayMs) : 0;
    this.payloadBytes = Number.isFinite(config.payloadBytes) && config.payloadBytes > 0 ? Math.floor(config.payloadBytes) : 1024;
    this.throttleEvery = Number.isFinite(config.throttleEvery) && config.throttleEvery > 0 ? Math.floor(config.throttleEvery) : 0;
    this.throttleStatus = Number.isFinite(config.throttleStatus) ? Math.floor(config.throttleStatus) : 429;

    const parsedSeed = new URL(this.seed);
    this.host = parsedSeed.hostname.toLowerCase();
    this.origin = parsedSeed.origin;
    this.basePath = parsedSeed.pathname.replace(/\/+$/, '') || '/';
    this.site = this.buildSite();
    this.totalPages = this.site.size;
  }

  buildSite() {
    const nodes = new Map();
    const queue = [{ url: this.seed, depth: 0, index: 0 }];
    while (queue.length > 0) {
      const current = queue.shift();
      const links = [];
      if (current.depth < this.depth) {
        for (let i = 0; i < this.branching; i += 1) {
          const childIndex = current.index * this.branching + i + 1;
          const childPath = `${this.basePath}/d${current.depth + 1}n${childIndex}`;
          const childUrl = new URL(childPath, this.origin).toString();
          queue.push({ url: childUrl, depth: current.depth + 1, index: childIndex });
          links.push(childUrl);
        }
      }
      nodes.set(current.url, {
        url: current.url,
        depth: current.depth,
        links,
        script: this.makeScriptPayload(current.depth, current.index),
      });
    }
    return nodes;
  }

  makeScriptPayload(depth, index) {
    const base = `console.log('node:${depth}:${index}')`; 
    if (this.payloadBytes <= base.length) {
      return base;
    }
    const filler = 'x'.repeat(this.payloadBytes - base.length);
    return `${base}${filler}`;
  }

  async fetch(url, attempt) {
    const node = this.site.get(url);
    if (!node) {
      throw new Error(`unexpected URL ${url}`);
    }
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }

    let status = 200;
    if (this.throttleEvery > 0 && attempt % this.throttleEvery === 0) {
      status = this.throttleStatus;
    }

    if (status >= 400 && status < 500) {
      return { status, links: [], scripts: [] };
    }

    return {
      status,
      links: node.links.slice(),
      scripts: [
        {
          src: '',
          content: node.script,
        },
      ],
    };
  }
}

function trackMemory(work) {
  return new Promise((resolve, reject) => {
    let peak = process.memoryUsage().rss;
    const timer = setInterval(() => {
      try {
        const usage = process.memoryUsage().rss;
        if (usage > peak) {
          peak = usage;
        }
      } catch (error) {
        clearInterval(timer);
        reject(error);
      }
    }, MEMORY_SAMPLE_INTERVAL_MS);

    (async () => {
      try {
        const result = await work();
        clearInterval(timer);
        const usage = process.memoryUsage().rss;
        if (usage > peak) {
          peak = usage;
        }
        resolve({ result, peak });
      } catch (error) {
        clearInterval(timer);
        reject(error);
      }
    })();
  });
}

function summariseScenario(config, runs) {
  const urlsPerMinute = runs.map((run) => run.urlsPerMinute);
  const banRates = runs.map((run) => run.banRate);
  const memoryPeaks = runs.map((run) => run.memoryPeakBytes);
  const cpuPercents = runs.map((run) => run.cpuPercent);
  const elapsed = runs.map((run) => run.elapsedMs);
  const attempts = runs.map((run) => run.attemptedRequests);
  const throttled = runs.map((run) => run.throttledResponses);

  return {
    name: config.name || 'unnamed',
    description: config.description || '',
    depth: config.depth,
    branching: config.branching,
    delayMs: config.delayMs,
    throttleEvery: config.throttleEvery || 0,
    iterations: runs.length,
    runs,
    metrics: {
      urlsPerMinute: makeStats(urlsPerMinute),
      banRate: makeStats(banRates),
      memoryPeakBytes: makeStats(memoryPeaks),
      cpuPercent: makeStats(cpuPercents),
      elapsedMs: makeStats(elapsed),
      attemptedRequests: makeStats(attempts),
      throttledResponses: makeStats(throttled),
    },
  };
}

function makeStats(values) {
  const list = values.filter((value) => Number.isFinite(value));
  if (list.length === 0) {
    return { count: 0 };
  }
  const sorted = list.slice().sort((a, b) => a - b);
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  const sum = sorted.reduce((acc, value) => acc + value, 0);
  const mean = sum / sorted.length;
  const median = sorted.length % 2 === 1
    ? sorted[(sorted.length - 1) / 2]
    : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2;

  return {
    count: sorted.length,
    min,
    max,
    mean,
    median,
  };
}

function loadScenarios(filePath) {
  const resolved = path.resolve(filePath);
  const raw = fs.readFileSync(resolved, 'utf8');
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) {
    throw new Error(`scenario file ${filePath} must contain an array`);
  }
  return parsed;
}

function loadBaseline(filePath) {
  try {
    const raw = fs.readFileSync(path.resolve(filePath), 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') {
      return { scenarios: {} };
    }
    return parsed;
  } catch (error) {
    if (error && error.code === 'ENOENT') {
      return { scenarios: {} };
    }
    throw error;
  }
}

function buildBaselinePayload(summaries) {
  const payload = {
    version: 1,
    generatedAt: new Date().toISOString(),
    scenarios: {},
  };
  for (const summary of summaries) {
    payload.scenarios[summary.name] = {
      medianUrlsPerMinute: summary.metrics.urlsPerMinute?.median || 0,
      medianBanRate: summary.metrics.banRate?.median || 0,
      medianMemoryPeakBytes: summary.metrics.memoryPeakBytes?.median || 0,
      medianCpuPercent: summary.metrics.cpuPercent?.median || 0,
      iterations: summary.iterations,
    };
  }
  return payload;
}

function compareAgainstBaseline(summaries, baseline, budget) {
  const comparisons = [];
  const failures = [];
  const baselineScenarios = baseline && baseline.scenarios ? baseline.scenarios : {};

  for (const summary of summaries) {
    const baselineEntry = baselineScenarios[summary.name];
    if (!baselineEntry) {
      continue;
    }
    const baselineValue = baselineEntry.medianUrlsPerMinute;
    const currentValue = summary.metrics.urlsPerMinute?.median;
    if (!Number.isFinite(baselineValue) || !Number.isFinite(currentValue) || baselineValue === 0) {
      continue;
    }
    const deltaPercent = ((currentValue - baselineValue) / baselineValue) * 100;
    comparisons.push({
      scenario: summary.name,
      baselineValue,
      currentValue,
      deltaPercent,
    });
    if (deltaPercent < -Math.abs(budget)) {
      failures.push({
        scenario: summary.name,
        metric: 'urls/min',
        baselineValue,
        currentValue,
        deltaPercent,
      });
    }
  }

  return { comparisons, failures };
}

function renderMarkdown(results, comparison, baseline, budget) {
  const lines = [];
  lines.push('# Excavator performance benchmarks');
  lines.push('');
  lines.push(`Generated at ${results.generatedAt}`);
  lines.push('');
  lines.push(`Iterations per scenario: ${results.iterations}`);
  lines.push('');

  for (const scenario of results.scenarios) {
    lines.push(`## ${scenario.name}`);
    if (scenario.description) {
      lines.push(scenario.description);
      lines.push('');
    }
    lines.push('| Metric | Median | Mean | Min | Max |');
    lines.push('| --- | ---: | ---: | ---: | ---: |');
    lines.push(
      `| URLs/min | ${formatNumber(scenario.metrics.urlsPerMinute?.median)} | ${formatNumber(
        scenario.metrics.urlsPerMinute?.mean
      )} | ${formatNumber(scenario.metrics.urlsPerMinute?.min)} | ${formatNumber(
        scenario.metrics.urlsPerMinute?.max
      )} |`
    );
    lines.push(
      `| Ban rate | ${formatPercent(scenario.metrics.banRate?.median)} | ${formatPercent(
        scenario.metrics.banRate?.mean
      )} | ${formatPercent(scenario.metrics.banRate?.min)} | ${formatPercent(
        scenario.metrics.banRate?.max
      )} |`
    );
    lines.push(
      `| Memory peak (MB) | ${formatMegabytes(scenario.metrics.memoryPeakBytes?.median)} | ${formatMegabytes(
        scenario.metrics.memoryPeakBytes?.mean
      )} | ${formatMegabytes(scenario.metrics.memoryPeakBytes?.min)} | ${formatMegabytes(
        scenario.metrics.memoryPeakBytes?.max
      )} |`
    );
    lines.push(
      `| CPU utilisation (%) | ${formatNumber(scenario.metrics.cpuPercent?.median)} | ${formatNumber(
        scenario.metrics.cpuPercent?.mean
      )} | ${formatNumber(scenario.metrics.cpuPercent?.min)} | ${formatNumber(
        scenario.metrics.cpuPercent?.max
      )} |`
    );
    lines.push('');
    lines.push('Iterations:');
    lines.push('');
    lines.push('| Iteration | URLs/min | Ban rate | Peak RSS (MB) | CPU % | Duration (ms) |');
    lines.push('| ---: | ---: | ---: | ---: | ---: | ---: |');
    for (const run of scenario.runs) {
      lines.push(
        `| ${run.iteration} | ${formatNumber(run.urlsPerMinute)} | ${formatPercent(run.banRate)} | ${formatMegabytes(
          run.memoryPeakBytes
        )} | ${formatNumber(run.cpuPercent)} | ${formatNumber(run.elapsedMs)} |`
      );
    }
    lines.push('');
    lines.push(`Trend sparkline (URLs/min): \`${renderSparkline(scenario.runs.map((run) => run.urlsPerMinute))}\``);
    lines.push('');
  }

  if (comparison && comparison.comparisons.length > 0) {
    lines.push('## Baseline comparison');
    lines.push('');
    lines.push(`Regression budget: -${Math.abs(budget)}%`);
    lines.push('');
    lines.push('| Scenario | Baseline (URLs/min) | Current (URLs/min) | Δ % |');
    lines.push('| --- | ---: | ---: | ---: |');
    for (const entry of comparison.comparisons) {
      lines.push(
        `| ${entry.scenario} | ${formatNumber(entry.baselineValue)} | ${formatNumber(entry.currentValue)} | ${formatNumber(
          entry.deltaPercent,
          2
        )}% |`
      );
    }
    lines.push('');
    if (comparison.failures.length > 0) {
      lines.push('⚠️ Regression budget exceeded. See log for details.');
      lines.push('');
    }
  } else if (baseline && Object.keys(baseline.scenarios || {}).length > 0) {
    lines.push('## Baseline comparison');
    lines.push('');
    lines.push('No matching baseline entries were found for the configured scenarios.');
    lines.push('');
  }

  return lines.join('\n');
}

function renderSparkline(values) {
  if (!Array.isArray(values) || values.length === 0) {
    return '';
  }
  const blocks = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
  const min = Math.min(...values);
  const max = Math.max(...values);
  if (!Number.isFinite(min) || !Number.isFinite(max) || min === max) {
    return blocks[0].repeat(values.length);
  }
  return values
    .map((value) => {
      if (!Number.isFinite(value)) {
        return blocks[0];
      }
      const ratio = (value - min) / (max - min);
      const index = Math.min(blocks.length - 1, Math.max(0, Math.round(ratio * (blocks.length - 1))));
      return blocks[index];
    })
    .join('');
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      continue;
    }
    const [flag, inline] = token.split('=', 2);
    const key = flag.slice(2);
    let value = inline;
    if (value === undefined) {
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        value = next;
        i += 1;
      } else {
        value = '';
      }
    }
    switch (key) {
      case 'scenarios':
        args.scenarios = value;
        break;
      case 'iterations':
        args.iterations = Number.parseInt(value, 10);
        break;
      case 'budget':
        args.budget = Number.parseFloat(value);
        break;
      case 'baseline':
        args.baseline = value;
        break;
      case 'update-baseline':
        args.updateBaseline = true;
        break;
      case 'json':
        args.json = value;
        break;
      case 'summary':
        args.summary = value;
        break;
      default:
        break;
    }
  }
  return args;
}

function formatNumber(value, digits = 1) {
  if (!Number.isFinite(value)) {
    return 'n/a';
  }
  return Number.parseFloat(value).toFixed(digits);
}

function formatPercent(value, digits = 2) {
  if (!Number.isFinite(value)) {
    return 'n/a';
  }
  return `${Number.parseFloat(value * 100).toFixed(digits)}%`;
}

function formatMegabytes(value) {
  if (!Number.isFinite(value)) {
    return 'n/a';
  }
  return formatNumber(value / (1024 * 1024));
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error && error.stack ? error.stack : error);
    process.exitCode = 1;
  });
}

module.exports = {
  SyntheticTarget,
  runBenchmarkIteration,
  executeScenario,
  renderSparkline,
  makeStats,
  buildBaselinePayload,
};
