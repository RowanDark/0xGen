// plugins/excavator/crawl.js
const { chromium } = require('playwright');
const { URL } = require('url');

const DEFAULT_MAX_DEPTH = Number.parseInt(process.env.EXCAVATOR_MAX_DEPTH || '', 10);
const DEFAULT_MAX_PAGES = Number.parseInt(process.env.EXCAVATOR_MAX_PAGES || '', 10);
const DEFAULT_TIMEOUT = Number.parseInt(process.env.EXCAVATOR_TIMEOUT_MS || '', 10);

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
    return url.toString();
  } catch (error) {
    return null;
  }
}

function parseAllowedHosts(seedURL, configuredHosts) {
  const seedHost = new URL(seedURL).hostname.toLowerCase();
  const allowed = new Set([seedHost]);
  for (const host of configuredHosts) {
    const trimmed = String(host || '').trim().toLowerCase();
    if (trimmed) {
      allowed.add(trimmed);
    }
  }
  return Array.from(allowed).sort();
}

function dedupeAndSort(values) {
  const seen = new Set();
  const result = [];
  for (const value of values) {
    if (!value) continue;
    if (seen.has(value)) continue;
    seen.add(value);
    result.push(value);
  }
  result.sort();
  return result;
}

function normaliseScripts(list, baseURL) {
  const seen = new Set();
  const result = [];
  for (const entry of list || []) {
    if (!entry || (typeof entry.src !== 'string' && typeof entry.content !== 'string')) {
      continue;
    }
    const rawSrc = entry.src ? entry.src.trim() : '';
    const src = rawSrc ? normaliseURL(rawSrc, baseURL) : null;
    const content = typeof entry.content === 'string' ? entry.content : '';
    const excerpt = content.trim().slice(0, 200) || null;
    const fingerprint = `${src || ''}|${excerpt || ''}`;
    if (seen.has(fingerprint)) {
      continue;
    }
    seen.add(fingerprint);
    result.push({
      src,
      content_excerpt: excerpt,
      size_bytes: content.length || null,
    });
  }
  result.sort((a, b) => {
    const aSrc = a.src || '';
    const bSrc = b.src || '';
    if (aSrc === bSrc) {
      return (a.content_excerpt || '').localeCompare(b.content_excerpt || '');
    }
    return aSrc.localeCompare(bSrc);
  });
  return result;
}

async function crawlSite(options) {
  const {
    seed,
    maxDepth = Number.isFinite(DEFAULT_MAX_DEPTH) && DEFAULT_MAX_DEPTH >= 0 ? DEFAULT_MAX_DEPTH : 1,
    maxPages = Number.isFinite(DEFAULT_MAX_PAGES) && DEFAULT_MAX_PAGES > 0 ? DEFAULT_MAX_PAGES : 25,
    allowedHosts: configuredHosts = [],
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

  const allowedHosts = parseAllowedHosts(seedNormalised, configuredHosts);
  const allowedHostSet = new Set(allowedHosts);

  const startedAt = now();

  const queue = [{ url: seedNormalised, depth: 0 }];
  const visited = new Set();
  const pages = [];
  let discoveredLinks = 0;

  while (queue.length > 0 && pages.length < maxPages) {
    const current = queue.shift();
    if (!current) break;
    if (visited.has(current.url)) {
      continue;
    }
    visited.add(current.url);

    const pageRecord = {
      url: current.url,
      resolved_url: current.url,
      depth: current.depth,
      status: null,
      title: null,
      error: null,
      links: [],
      scripts: [],
    };

    let pageData;
    try {
      pageData = await fetchPage(current.url, current.depth);
    } catch (error) {
      pageRecord.error = error && error.message ? String(error.message) : 'unknown fetch error';
      pages.push(pageRecord);
      continue;
    }

    const resolved = normaliseURL(pageData.url || current.url) || current.url;
    pageRecord.resolved_url = resolved;
    if (!visited.has(resolved)) {
      visited.add(resolved);
    }

    if (typeof pageData.status === 'number') {
      pageRecord.status = pageData.status;
    }
    if (typeof pageData.title === 'string' && pageData.title.trim() !== '') {
      pageRecord.title = pageData.title.trim();
    }

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
      if (current.depth < maxDepth && !visited.has(normalised) && queue.every((item) => item.url !== normalised)) {
        queue.push({ url: normalised, depth: current.depth + 1 });
      }
    }

    const uniqueLinks = dedupeAndSort(links);
    discoveredLinks += uniqueLinks.length;
    pageRecord.links = uniqueLinks;
    pageRecord.scripts = normaliseScripts(pageData.scripts || [], resolved);
    pages.push(pageRecord);
  }

  const finishedAt = now();

  return {
    seed: seedNormalised,
    started_at: startedAt.toISOString(),
    finished_at: finishedAt.toISOString(),
    config: {
      max_depth: maxDepth,
      max_pages: maxPages,
      allowed_hosts: allowedHosts,
    },
    stats: {
      pages_visited: pages.length,
      links_discovered: discoveredLinks,
    },
    pages,
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
    const links = await page.$$eval('a[href]', (elements) =>
      elements
        .map((el) => el.getAttribute('href'))
        .filter((value) => typeof value === 'string')
    );
    const scripts = await page.$$eval('script', (elements) =>
      elements.map((el) => ({
        src: el.getAttribute('src') || '',
        content: el.textContent || '',
      }))
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
  const seed = process.env.TARGET_URL || process.argv[2] || 'https://example.com';
  const allowedHostsEnv = (process.env.EXCAVATOR_ALLOWED_HOSTS || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

  const timeout = Number.isFinite(DEFAULT_TIMEOUT) && DEFAULT_TIMEOUT > 0 ? DEFAULT_TIMEOUT : undefined;

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  try {
    const result = await crawlSite({
      seed,
      maxDepth: Number.isFinite(DEFAULT_MAX_DEPTH) && DEFAULT_MAX_DEPTH >= 0 ? DEFAULT_MAX_DEPTH : 1,
      maxPages: Number.isFinite(DEFAULT_MAX_PAGES) && DEFAULT_MAX_PAGES > 0 ? DEFAULT_MAX_PAGES : 25,
      allowedHosts: allowedHostsEnv,
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

module.exports = { crawlSite, normaliseURL };
