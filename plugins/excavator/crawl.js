// plugins/excavator/crawl.js
const { chromium } = require('playwright');
const { URL } = require('url');

const MAX_LINKS = 200;
const MAX_SCRIPTS = 100;
const MAX_LINK_ELEMENTS = 400;
const MAX_SCRIPT_ELEMENTS = 200;
const SCRIPT_SNIPPET_LIMIT = 200;

const DEFAULT_MAX_DEPTH = Number.parseInt(
  process.env.DEPTH || process.env.EXCAVATOR_MAX_DEPTH || '',
  10
);
const DEFAULT_MAX_PAGES = Number.parseInt(
  process.env.MAX_PAGES || process.env.EXCAVATOR_MAX_PAGES || '',
  10
);
const DEFAULT_HOST_LIMIT = Number.parseInt(
  process.env.HOST_LIMIT || process.env.EXCAVATOR_HOST_LIMIT || '',
  10
);
const DEFAULT_TIMEOUT = Number.parseInt(
  process.env.TIMEOUT || process.env.TIMEOUT_MS || process.env.EXCAVATOR_TIMEOUT_MS || '',
  10
);

function normaliseURL(href, base) {
  if (typeof href !== 'string' || href.trim() === '') {
    return null;
  }
  try {
    const url = base ? new URL(href, base) : new URL(href);
    if (!/^https?:$/.test(url.protocol)) {
      return null;
    }
    url.hash = '';
    if ((url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443')) {
      url.port = '';
    }
    let pathname = url.pathname || '/';
    pathname = pathname.replace(/\/{2,}/g, '/');
    if (!pathname.startsWith('/')) {
      pathname = `/${pathname}`;
    }
    if (pathname.length > 1 && pathname.endsWith('/')) {
      pathname = pathname.replace(/\/+$/, '');
      if (pathname === '') {
        pathname = '/';
      }
    }
    url.pathname = pathname;

    if (url.search) {
      const params = Array.from(url.searchParams.entries());
      params.sort((a, b) => {
        if (a[0] === b[0]) {
          return a[1].localeCompare(b[1]);
        }
        return a[0].localeCompare(b[0]);
      });
      const canonical = new URLSearchParams();
      for (const [key, value] of params) {
        canonical.append(key, value);
      }
      const serialised = canonical.toString();
      url.search = serialised ? `?${serialised}` : '';
    }
    const serialised = url.toString();
    if ((url.pathname === '/' || url.pathname === '') && !url.search) {
      return serialised.endsWith('/') ? serialised.slice(0, -1) : serialised;
    }
    return serialised;
  } catch (error) {
    return null;
  }
}

function parseAllowedHosts(seedURL, configuredHosts, hostLimit) {
  const seedHost = new URL(seedURL).hostname.toLowerCase();
  const ordered = [seedHost];
  const seen = new Set(ordered);

  for (const host of configuredHosts) {
    const trimmed = String(host || '').trim().toLowerCase();
    if (trimmed && !seen.has(trimmed)) {
      ordered.push(trimmed);
      seen.add(trimmed);
    }
  }

  let limit = Number.isFinite(hostLimit) && hostLimit > 0 ? Math.floor(hostLimit) : null;
  if (limit !== null && limit < 1) {
    limit = 1;
  }

  let constrained = ordered;
  if (limit !== null && ordered.length > limit) {
    if (!ordered.slice(0, limit).includes(seedHost)) {
      const withoutSeed = ordered.filter((entry) => entry !== seedHost);
      constrained = [seedHost, ...withoutSeed];
    }
    constrained = constrained.slice(0, limit);
    if (!constrained.includes(seedHost)) {
      constrained[constrained.length - 1] = seedHost;
    }
  }

  const sorted = Array.from(new Set(constrained)).sort();
  return sorted;
}

function collectScripts(list, baseURL, aggregate, seen) {
  if (aggregate.length >= MAX_SCRIPTS) {
    return;
  }
  for (const entry of list || []) {
    if (aggregate.length >= MAX_SCRIPTS) {
      break;
    }
    if (!entry || (typeof entry.src !== 'string' && typeof entry.content !== 'string')) {
      continue;
    }
    const rawSrc = entry.src ? entry.src.trim() : '';
    const src = rawSrc ? normaliseURL(rawSrc, baseURL) : null;
    const content = typeof entry.content === 'string' ? entry.content : '';
    const snippet = content.trim().slice(0, SCRIPT_SNIPPET_LIMIT);
    if (!src && !snippet) {
      continue;
    }
    const fingerprint = `${src || ''}|${snippet}`;
    if (seen.has(fingerprint)) {
      continue;
    }
    seen.add(fingerprint);
    aggregate.push({
      src,
      snippet,
    });
  }
}

async function crawlSite(options) {
  const {
    seed,
    maxDepth = Number.isFinite(DEFAULT_MAX_DEPTH) && DEFAULT_MAX_DEPTH >= 0 ? DEFAULT_MAX_DEPTH : 1,
    maxPages = Number.isFinite(DEFAULT_MAX_PAGES) && DEFAULT_MAX_PAGES > 0 ? DEFAULT_MAX_PAGES : 25,
    allowedHosts: configuredHosts = [],
    hostLimit = Number.isFinite(DEFAULT_HOST_LIMIT) && DEFAULT_HOST_LIMIT > 0 ? DEFAULT_HOST_LIMIT : null,
    fetchPage,
    now = () => new Date(),
  } = options;

  if (typeof fetchPage !== 'function') {
    throw new Error('fetchPage function is required');
  }

  const seedNormalised = normaliseURL(seed);
  if (!seedNormalised) {
    throw new Error('seed URL must be an absolute HTTP(S) URL');
  }

  const depthLimit = Number.isFinite(maxDepth) && maxDepth >= 0 ? Math.floor(maxDepth) : 1;
  const pageLimit = Number.isFinite(maxPages) && maxPages > 0 ? Math.floor(maxPages) : 25;
  const hostLimitValue = Number.isFinite(hostLimit) && hostLimit > 0 ? Math.floor(hostLimit) : null;

  const allowedHosts = parseAllowedHosts(seedNormalised, configuredHosts, hostLimitValue);
  const allowedHostSet = new Set(allowedHosts);

  // Prime the clock so deterministic tests can control the finish timestamp.
  now();

  const queue = [{ url: seedNormalised, depth: 0 }];
  const enqueued = new Set([seedNormalised]);
  const visited = new Set();
  const aggregateLinks = new Set();
  const aggregateScripts = [];
  const scriptFingerprints = new Set();
  let pagesVisited = 0;

  while (queue.length > 0 && pagesVisited < pageLimit) {
    const current = queue.shift();
    if (!current) break;
    if (visited.has(current.url)) {
      continue;
    }
    visited.add(current.url);

    let pageData;
    try {
      pageData = await fetchPage(current.url, current.depth);
    } catch (error) {
      continue;
    }

    const resolved = normaliseURL(pageData.url || current.url) || current.url;
    if (!visited.has(resolved)) {
      visited.add(resolved);
    }

    pagesVisited += 1;

    const links = [];
    for (const raw of pageData.links || []) {
      const normalised = normaliseURL(raw, resolved);
      if (!normalised) {
        continue;
      }
      const host = new URL(normalised).hostname.toLowerCase();
      if (!allowedHostSet.has(host)) {
        continue;
      }
      links.push(normalised);
      if (current.depth < depthLimit && !visited.has(normalised) && !enqueued.has(normalised)) {
        queue.push({ url: normalised, depth: current.depth + 1 });
        enqueued.add(normalised);
      }
    }

    for (const link of links) {
      aggregateLinks.add(link);
    }

    collectScripts(pageData.scripts || [], resolved, aggregateScripts, scriptFingerprints);
  }

  const finishedAt = now();

  return {
    target: seedNormalised,
    links: Array.from(aggregateLinks)
      .sort()
      .slice(0, MAX_LINKS),
    scripts: aggregateScripts
      .slice()
      .sort((a, b) => {
        const aSrc = a.src || '';
        const bSrc = b.src || '';
        if (aSrc === bSrc) {
          return a.snippet.localeCompare(b.snippet);
        }
        return aSrc.localeCompare(bSrc);
      })
      .slice(0, MAX_SCRIPTS),
    meta: {
      crawled_at: finishedAt.toISOString(),
      depth: depthLimit,
    },
  };
}

async function fetchWithPlaywright(page, url, timeout) {
  try {
    const response = await page.goto(url, {
      waitUntil: 'networkidle',
      timeout: timeout && Number.isFinite(timeout) ? timeout : 45000,
    });
    const resolvedUrl = response ? response.url() : page.url();
    const title = await page.title();
    const links = await page.$$eval(
      'a[href]',
      (elements, limit) =>
        Array.from(elements)
          .slice(0, limit)
          .map((el) => el.getAttribute('href'))
          .filter((value) => typeof value === 'string' && value.trim() !== ''),
      MAX_LINK_ELEMENTS
    );
    const scripts = await page.$$eval(
      'script',
      (elements, limit) =>
        Array.from(elements)
          .slice(0, limit)
          .map((el) => ({
            src: el.getAttribute('src') || '',
            content: el.textContent || '',
          })),
      MAX_SCRIPT_ELEMENTS
    );
    return {
      url: resolvedUrl,
      status: response ? response.status() : null,
      title,
      links,
      scripts,
    };
  } catch (error) {
    throw new Error(`navigate ${url}: ${error.message}`);
  }
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  const seed =
    args.target ||
    process.env.TARGET ||
    process.env.TARGET_URL ||
    process.env.EXCAVATOR_TARGET ||
    'https://example.com';

  const envHosts = `${process.env.ALLOWED_HOSTS || process.env.EXCAVATOR_ALLOWED_HOSTS || ''}`
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  const allowedHostsEnv = [...envHosts, ...(args.allowedHosts || [])];

  const timeoutEnv = Number.isFinite(DEFAULT_TIMEOUT) && DEFAULT_TIMEOUT > 0 ? DEFAULT_TIMEOUT : null;
  const timeoutCli = parseInteger(args.timeout);
  const timeout =
    timeoutCli !== null ? timeoutCli : timeoutEnv !== null ? timeoutEnv : undefined;

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  try {
    const depthArg = parseInteger(args.depth);
    const maxPagesArg = parseInteger(args.maxPages);
    const hostLimitArg = parseInteger(args.hostLimit);

    const result = await crawlSite({
      seed,
      maxDepth:
        depthArg !== null ? depthArg : Number.isFinite(DEFAULT_MAX_DEPTH) ? DEFAULT_MAX_DEPTH : undefined,
      maxPages:
        maxPagesArg !== null
          ? maxPagesArg
          : Number.isFinite(DEFAULT_MAX_PAGES)
          ? DEFAULT_MAX_PAGES
          : undefined,
      allowedHosts: allowedHostsEnv,
      hostLimit:
        hostLimitArg !== null
          ? hostLimitArg
          : Number.isFinite(DEFAULT_HOST_LIMIT) && DEFAULT_HOST_LIMIT > 0
          ? DEFAULT_HOST_LIMIT
          : undefined,
      fetchPage: (targetUrl) => fetchWithPlaywright(page, targetUrl, timeout),
    });
    console.log(JSON.stringify(result, null, 2));
    await page.close();
    await browser.close();
    process.exit(0);
  } catch (error) {
    console.error('crawl error:', error.message || error);
    try {
      await page.close();
    } catch (closeError) {
      // ignore close errors
    }
    await browser.close();
    process.exit(2);
  }
}

if (require.main === module) {
  run();
}

function parseArgs(argv) {
  const result = {
    allowedHosts: [],
  };
  const positional = [];

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      positional.push(token);
      continue;
    }

    const [flag, inlineValue] = token.split('=', 2);
    const key = flag.slice(2).toLowerCase();
    let value = inlineValue;
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
      case 'target':
      case 'target-url':
        result.target = value;
        break;
      case 'depth':
        result.depth = value;
        break;
      case 'max-pages':
        result.maxPages = value;
        break;
      case 'host-limit':
        result.hostLimit = value;
        break;
      case 'timeout':
      case 'timeout-ms':
        result.timeout = value;
        break;
      case 'allowed-host':
        if (value) {
          result.allowedHosts.push(value);
        }
        break;
      case 'allowed-hosts':
        if (value) {
          result.allowedHosts.push(
            ...value
              .split(',')
              .map((item) => item.trim())
              .filter(Boolean)
          );
        }
        break;
      default:
        break;
    }
  }

  if (!result.target && positional.length > 0) {
    result.target = positional[0];
  }

  return result;
}

function parseInteger(value) {
  if (value === undefined || value === null || value === '') {
    return null;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? Math.floor(value) : null;
  }
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

module.exports = { crawlSite, normaliseURL, parseArgs };
