// plugins/excavator/crawl.js
const fs = require('node:fs');
const { chromium } = require('playwright');
const http = require('node:http');
const https = require('node:https');
const { URL } = require('url');

const { createScopeChecker } = require('./scope');

const MAX_LINKS = 200;
const MAX_SCRIPTS = 100;
const MAX_LINK_ELEMENTS = 400;
const MAX_SCRIPT_ELEMENTS = 200;
const SCRIPT_SNIPPET_LIMIT = 200;
const MAX_VISITED_PAGES = 50;

const DEFAULT_DEPTH = Number.parseInt(
  process.env.DEPTH || process.env.EXCAVATOR_MAX_DEPTH || '',
  10
);
const DEFAULT_HOST_LIMIT = Number.parseInt(
  process.env.HOST_LIMIT || process.env.EXCAVATOR_HOST_LIMIT || '',
  10
);
const DEFAULT_TIMEOUT = Number.parseInt(
  process.env.TIMEOUT_MS || process.env.TIMEOUT || process.env.EXCAVATOR_TIMEOUT_MS || '',
  10
);

function normaliseURL(href, base) {
  if (typeof href !== 'string' || href.trim() === '') {
    return null;
  }
  try {
    const url = base ? new URL(href, base) : new URL(href);
    if (!/^(https?|ftp):$/.test(url.protocol)) {
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

function collectScripts(list, baseURL, aggregate, seen, scopeGuard) {
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
      if (rawSrc && scopeGuard) {
        try {
          const parsed = new URL(rawSrc, baseURL).toString();
          scopeGuard.check(parsed, { stage: 'script', from: baseURL });
        } catch (error) {
          // ignore parse errors
        }
      }
      continue;
    }
    if (src && scopeGuard && !scopeGuard.check(src, { stage: 'script', from: baseURL })) {
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
    depth = Number.isFinite(DEFAULT_DEPTH) && DEFAULT_DEPTH >= 0 ? DEFAULT_DEPTH : 1,
    hostLimit = Number.isFinite(DEFAULT_HOST_LIMIT) && DEFAULT_HOST_LIMIT > 0 ? DEFAULT_HOST_LIMIT : 1,
    fetchPage,
    now = () => new Date(),
    scope = 'origin',
    scopeAllowlist = [],
    unsafeFollow = false,
    allowPrivate = false,
    allowedProtocols,
    scopeLogger,
    delayMs = 0,
    maxPages = MAX_VISITED_PAGES,
    wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  } = options;

  if (typeof fetchPage !== 'function') {
    throw new Error('fetchPage function is required');
  }

  const seedNormalised = normaliseURL(seed);
  if (!seedNormalised) {
    throw new Error('seed URL must be an absolute HTTP(S) URL');
  }

  const depthLimit = Number.isFinite(depth) && depth >= 0 ? Math.floor(depth) : 1;
  const hostLimitValue = Number.isFinite(hostLimit) && hostLimit > 0 ? Math.floor(hostLimit) : 1;

  const seedUrl = new URL(seedNormalised);
  const seedHost = seedUrl.hostname.toLowerCase();
  const seedOrigin = seedUrl.origin;

  const delayInterval = Number.isFinite(delayMs) && delayMs > 0 ? Math.floor(delayMs) : 0;
  const maxPagesLimit = Number.isFinite(maxPages) && maxPages > 0 ? Math.floor(maxPages) : MAX_VISITED_PAGES;

  const unsafeFollowEnabled = parseBoolean(unsafeFollow);
  const allowPrivateEnabled = parseBoolean(allowPrivate);
  const allowlist = (Array.isArray(scopeAllowlist) ? scopeAllowlist : [scopeAllowlist])
    .filter((value) => typeof value === 'string' && value.trim() !== '');

  if (allowlist.length === 0) {
    throw new Error('scope allowlist must contain at least one entry');
  }

  const scopeGuard = createScopeChecker(scope, {
    seedUrl,
    seedHost,
    seedOrigin,
    allowlist,
    unsafeFollow: unsafeFollowEnabled,
    allowPrivate: allowPrivateEnabled,
    allowedProtocols,
    logger: typeof scopeLogger === 'function' ? scopeLogger : undefined,
  });

  if (!scopeGuard.check(seedNormalised, { stage: 'seed' })) {
    throw new Error('seed URL is outside the configured scope allowlist');
  }

  // Prime the clock so deterministic tests can control the finish timestamp.
  now();

  const queue = [{ url: seedNormalised, depth: 0 }];
  const enqueued = new Set([seedNormalised]);
  const visited = new Set();
  const aggregateLinks = new Set([seedNormalised]);
  const aggregateScripts = [];
  const scriptFingerprints = new Set();
  const allowedHosts = new Set([seedHost]);
  let pagesVisited = 0;

  while (queue.length > 0 && pagesVisited < maxPagesLimit) {
    const current = queue.shift();
    if (!current) break;
    if (visited.has(current.url)) {
      continue;
    }

    let pageData;
    try {
      if (delayInterval > 0 && pagesVisited > 0) {
        await wait(delayInterval);
      }
      pageData = await fetchPage(current.url, current.depth);
    } catch (error) {
      continue;
    }

    const resolved = normaliseURL(pageData.url || current.url) || current.url;
    if (visited.has(resolved)) {
      continue;
    }

    let resolvedHost;
    try {
      resolvedHost = new URL(resolved).hostname.toLowerCase();
    } catch (error) {
      resolvedHost = seedHost;
    }

    if (!scopeGuard.check(resolved, { stage: 'page', from: current.url })) {
      visited.add(resolved);
      continue;
    }

    if (!allowedHosts.has(resolvedHost)) {
      if (allowedHosts.size >= hostLimitValue) {
        visited.add(resolved);
        continue;
      }
      allowedHosts.add(resolvedHost);
    }

    visited.add(resolved);
    pagesVisited += 1;

    aggregateLinks.add(resolved);

    const links = Array.isArray(pageData.links) ? pageData.links : [];
    for (const raw of links) {
      let candidate;
      try {
        candidate = new URL(raw, resolved);
      } catch (error) {
        continue;
      }

      const candidateSerialised = candidate.toString();
      const normalised = normaliseURL(raw, resolved);
      if (!normalised) {
        scopeGuard.check(candidateSerialised, { stage: 'link', from: resolved });
        continue;
      }

      let linkURL;
      try {
        linkURL = new URL(normalised);
      } catch (error) {
        continue;
      }

      const followableProtocol = linkURL.protocol === 'http:' || linkURL.protocol === 'https:';
      const linkHost = linkURL.hostname.toLowerCase();
      const hostAlreadyAllowed = allowedHosts.has(linkHost);
      const canAdmitHost = hostAlreadyAllowed || allowedHosts.size < hostLimitValue;
      const canIncludeLink = hostAlreadyAllowed || !followableProtocol || depthLimit === 0 || canAdmitHost;

      if (!scopeGuard.check(normalised, { stage: 'link', from: resolved }) || !canIncludeLink) {
        continue;
      }

      if (
        followableProtocol &&
        current.depth < depthLimit &&
        canAdmitHost &&
        !visited.has(normalised) &&
        !enqueued.has(normalised)
      ) {
        if (!hostAlreadyAllowed) {
          allowedHosts.add(linkHost);
        }
        queue.push({ url: normalised, depth: current.depth + 1 });
        enqueued.add(normalised);
      }

      aggregateLinks.add(normalised);
    }

    collectScripts(
      pageData.scripts || [],
      resolved,
      aggregateScripts,
      scriptFingerprints,
      scopeGuard
    );
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
      allowed_hosts: Array.from(allowedHosts)
        .map((host) => host.toLowerCase())
        .sort(),
    },
  };
}

async function fetchWithPlaywright(page, url, timeout) {
  try {
    const response = await page.goto(url, {
      waitUntil: 'load',
      timeout: timeout && Number.isFinite(timeout) ? timeout : 45000,
    });
    await page.waitForTimeout(250);
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

  const timeoutEnv = Number.isFinite(DEFAULT_TIMEOUT) && DEFAULT_TIMEOUT > 0 ? DEFAULT_TIMEOUT : null;
  const timeoutCli = parseInteger(args.timeoutMs);
  const timeout = timeoutCli !== null ? timeoutCli : timeoutEnv !== null ? timeoutEnv : undefined;

  const normalisedSeed = normaliseURL(seed);

  const scopeArg = typeof args.scope === 'string' ? args.scope : undefined;
  const allowlistArg = (Array.isArray(args.allowlist) ? args.allowlist : args.allowlist ? [args.allowlist] : [])
    .map((value) => (typeof value === 'string' ? value.trim() : value))
    .filter((value) => typeof value === 'string' && value !== '');
  const unsafeFollowArg = args.unsafeFollow;
  const allowPrivateArg = args.allowPrivate;
  const allowedProtocolsRaw = Array.isArray(args.allowedProtocols)
    ? args.allowedProtocols
    : args.allowedProtocols
    ? [args.allowedProtocols]
    : [];
  const allowedProtocolsArg = allowedProtocolsRaw
    .map((value) => (typeof value === 'string' ? value.trim() : value))
    .filter((value) => typeof value === 'string' && value !== '');
  const allowedProtocolsList = allowedProtocolsArg.length > 0 ? allowedProtocolsArg : undefined;

  if (allowlistArg.length === 0) {
    throw new Error('at least one --scope-allow entry is required');
  }

  if (parseBoolean(unsafeFollowArg)) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        type: 'scope_warning',
        message: '--unsafe-follow enabled; out-of-allowlist URLs will be followed.',
      })
    );
  }

  const proxyServer =
    (typeof args.proxy === 'string' && args.proxy.trim() !== '' && args.proxy) ||
    process.env.EXCAVATOR_PROXY ||
    process.env.PROXY ||
    process.env.HTTP_PROXY ||
    process.env.HTTPS_PROXY ||
    process.env.ALL_PROXY ||
    '';

  const launchOptions = { headless: true };
  if (typeof proxyServer === 'string' && proxyServer.trim() !== '') {
    launchOptions.proxy = { server: proxyServer.trim() };
  }

  let browser;
  try {
    browser = await chromium.launch(launchOptions);
  } catch (error) {
    if (isMissingBrowserError(error)) {
      const fallback = await crawlWithHTTP({
        seed: normalisedSeed || seed,
        proxy: typeof proxyServer === 'string' ? proxyServer.trim() : '',
        now: () => new Date(),
        timeout,
        scope: scopeArg,
        scopeAllowlist: allowlistArg,
        unsafeFollow: unsafeFollowArg,
        allowPrivate: allowPrivateArg,
        allowedProtocols: allowedProtocolsList,
      });
      console.log(JSON.stringify(fallback, null, 2));
      process.exit(0);
    }
    throw error;
  }
  const context = await browser.newContext();

  try {
    const seedForCookies = normalisedSeed ? new URL(normalisedSeed) : new URL(seed);
    const cookieHeaders = collectCookieHeaders(args);
    const initialCookies = buildInitialCookies(cookieHeaders, seedForCookies);
    if (initialCookies.length > 0) {
      await context.addCookies(initialCookies);
    }
  } catch (cookieError) {
    await context.close();
    await browser.close();
    throw cookieError;
  }

  const page = await context.newPage();
  try {
    const depthArg = parseInteger(args.depth);
    const hostLimitArg = parseInteger(args.hostLimit);
    const delayArg = parseInteger(args.delayMs);
    const maxPagesArg = parseInteger(args.maxPages);

    const result = await crawlSite({
      seed,
      depth:
        depthArg !== null ? depthArg : Number.isFinite(DEFAULT_DEPTH) ? DEFAULT_DEPTH : undefined,
      hostLimit:
        hostLimitArg !== null
          ? hostLimitArg
          : Number.isFinite(DEFAULT_HOST_LIMIT) && DEFAULT_HOST_LIMIT > 0
          ? DEFAULT_HOST_LIMIT
          : undefined,
      fetchPage: (targetUrl) => fetchWithPlaywright(page, targetUrl, timeout),
      scope: scopeArg,
      scopeAllowlist: allowlistArg,
      unsafeFollow: unsafeFollowArg,
      allowPrivate: allowPrivateArg,
      allowedProtocols: allowedProtocolsList,
      delayMs: delayArg !== null ? delayArg : undefined,
      maxPages: maxPagesArg !== null ? maxPagesArg : undefined,
      wait: sleep,
    });
    console.log(JSON.stringify(result, null, 2));
    await page.close();
    await context.close();
    await browser.close();
    process.exit(0);
  } catch (error) {
    console.error('crawl error:', error.message || error);
    try {
      await page.close();
    } catch (closeError) {
      // ignore close errors
    }
    try {
      await context.close();
    } catch (contextError) {
      // ignore context close errors
    }
    await browser.close();
    process.exit(2);
  }
}

if (require.main === module) {
  run();
}

function parseArgs(argv) {
  const result = {};
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
        result.target = value;
        break;
      case 'depth':
        result.depth = value;
        break;
      case 'host-limit':
        result.hostLimit = value;
        break;
      case 'timeout-ms':
        result.timeoutMs = value;
        break;
      case 'delay-ms':
        result.delayMs = value;
        break;
      case 'max-pages':
        result.maxPages = value;
        break;
      case 'scope':
        result.scope = value;
        break;
      case 'proxy':
        result.proxy = value;
        break;
      case 'allow':
      case 'allowlist':
      case 'scope-allow':
      case 'scope-allowlist':
        if (value !== undefined) {
          if (!result.allowlist) {
            result.allowlist = [];
          }
          if (Array.isArray(value)) {
            for (const entry of value) {
              if (entry) {
                result.allowlist.push(entry);
              }
            }
          } else if (value) {
            result.allowlist.push(value);
          }
        }
        break;
      case 'unsafe-follow':
        result.unsafeFollow = value;
        break;
      case 'allow-private':
        result.allowPrivate = value;
        break;
      case 'allow-protocol':
      case 'allow-protocols':
      case 'protocol-allow':
      case 'scope-allow-protocol':
        if (value !== undefined) {
          if (!result.allowedProtocols) {
            result.allowedProtocols = [];
          }
          const entries = Array.isArray(value)
            ? value
            : typeof value === 'string'
            ? value.split(',')
            : [value];
          for (const entry of entries) {
            if (typeof entry === 'string' && entry.trim() !== '') {
              result.allowedProtocols.push(entry.trim());
            }
          }
        }
        break;
      case 'cookie':
        if (!result.cookie) {
          result.cookie = [];
        }
        if (value) {
          result.cookie.push(value);
        }
        break;
      case 'cookie-file':
        if (!result.cookieFile) {
          result.cookieFile = [];
        }
        if (value) {
          result.cookieFile.push(value);
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

function parseBoolean(value) {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return value !== 0;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim().toLowerCase();
    if (trimmed === '') {
      return true;
    }
    return !['false', '0', 'no', 'off'].includes(trimmed);
  }
  if (value === null || value === undefined) {
    return false;
  }
  return Boolean(value);
}

module.exports = { crawlSite, normaliseURL, parseArgs };

function isMissingBrowserError(error) {
  if (!error) {
    return false;
  }
  const message = String(error && error.message ? error.message : error);
  return (
    message.includes('Executable doesn\'t exist') ||
    message.includes('playwright install') ||
    message.includes('browserType.launch')
  );
}

async function crawlWithHTTP(options) {
  const {
    seed,
    proxy,
    now = () => new Date(),
    timeout,
    scope = 'origin',
    scopeAllowlist = [],
    unsafeFollow = false,
    allowPrivate = false,
    allowedProtocols,
    scopeLogger,
  } = options;
  const normalised = normaliseURL(seed);
  if (!normalised) {
    throw new Error('seed URL must be an absolute HTTP(S) URL');
  }
  const response = await fetchViaHTTP(normalised, proxy, timeout);
  const baseURL = normaliseURL(response.url) || normalised;

  const seedUrl = new URL(normalised);
  const allowlist = (Array.isArray(scopeAllowlist) ? scopeAllowlist : [scopeAllowlist])
    .filter((value) => typeof value === 'string' && value.trim() !== '');

  if (allowlist.length === 0) {
    throw new Error('scope allowlist must contain at least one entry');
  }

  const scopeGuard = createScopeChecker(scope, {
    seedUrl,
    seedHost: seedUrl.hostname.toLowerCase(),
    seedOrigin: seedUrl.origin,
    allowlist,
    unsafeFollow: parseBoolean(unsafeFollow),
    allowPrivate: parseBoolean(allowPrivate),
    allowedProtocols,
    logger: typeof scopeLogger === 'function' ? scopeLogger : undefined,
  });

  if (!scopeGuard.check(normalised, { stage: 'seed' })) {
    throw new Error('seed URL is outside the configured scope allowlist');
  }

  if (!scopeGuard.check(baseURL, { stage: 'page', from: normalised })) {
    throw new Error('resolved URL is outside the configured scope allowlist');
  }

  const rawLinks = extractLinks(response.body, baseURL);
  const links = rawLinks.filter((link) => scopeGuard.check(link, { stage: 'link', from: baseURL }));
  const rawScripts = extractScripts(response.body, baseURL);
  const scripts = rawScripts.filter(
    (entry) => !entry.src || scopeGuard.check(entry.src, { stage: 'script', from: baseURL })
  );
  const host = new URL(baseURL).hostname.toLowerCase();

  return {
    target: normalised,
    links,
    scripts,
    meta: {
      crawled_at: now().toISOString(),
      depth: 0,
      allowed_hosts: [host],
    },
  };
}

function extractLinks(html, baseURL) {
  const seen = new Set();
  const results = [];
  if (typeof html !== 'string' || html.trim() === '') {
    return [baseURL];
  }
  const linkRe = /<a\s+[^>]*href\s*=\s*"([^"]+)"/gi;
  let match;
  while ((match = linkRe.exec(html)) !== null) {
    const candidate = normaliseURL(match[1], baseURL);
    if (!candidate || seen.has(candidate)) {
      continue;
    }
    seen.add(candidate);
    results.push(candidate);
  }
  if (!seen.has(baseURL)) {
    results.unshift(baseURL);
  }
  return results.slice(0, MAX_LINKS);
}

function extractScripts(html, baseURL) {
  const seen = new Set();
  const scripts = [];
  if (typeof html !== 'string' || html.trim() === '') {
    return scripts;
  }
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let match;
  while ((match = scriptRe.exec(html)) !== null) {
    if (scripts.length >= MAX_SCRIPTS) {
      break;
    }
    const attrs = match[1] || '';
    const body = match[2] || '';
    const srcMatch = /src\s*=\s*"([^"]+)"/i.exec(attrs);
    const src = srcMatch ? normaliseURL(srcMatch[1], baseURL) : null;
    const snippet = body.trim().slice(0, SCRIPT_SNIPPET_LIMIT);
    const fingerprint = `${src || ''}|${snippet}`;
    if (fingerprint.trim() === '' || seen.has(fingerprint)) {
      continue;
    }
    seen.add(fingerprint);
    scripts.push({ src, snippet });
  }
  return scripts;
}

async function fetchViaHTTP(target, proxy, timeout) {
  const url = new URL(target);
  const useProxy = typeof proxy === 'string' && proxy.trim() !== '';
  const client = useProxy ? http : url.protocol === 'https:' ? https : http;
  const proxyURL = useProxy ? new URL(proxy) : null;
  const requestOptions = useProxy
    ? {
        host: proxyURL.hostname,
        port: proxyURL.port || (proxyURL.protocol === 'https:' ? 443 : 80),
        method: 'GET',
        path: target,
        headers: { Host: url.host },
      }
    : {
        host: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        method: 'GET',
        path: (url.pathname || '/') + (url.search || ''),
        headers: { Host: url.host },
      };

  requestOptions.family = 4;

  if (timeout && Number.isFinite(timeout)) {
    requestOptions.timeout = timeout;
  }

  return new Promise((resolve, reject) => {
    const req = client.request(requestOptions, (res) => {
      const chunks = [];
      res.on('data', (chunk) => {
        chunks.push(Buffer.from(chunk));
      });
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        resolve({
          url: res.headers.location ? res.headers.location : target,
          status: res.statusCode || 0,
          body,
        });
      });
    });
    req.on('error', (err) => {
      reject(err);
    });
    req.end();
  });
}

function collectCookieHeaders(args) {
  const headers = [];
  if (Array.isArray(args.cookie)) {
    for (const entry of args.cookie) {
      if (typeof entry === 'string' && entry.trim() !== '') {
        headers.push(entry.trim());
      }
    }
  } else if (typeof args.cookie === 'string' && args.cookie.trim() !== '') {
    headers.push(args.cookie.trim());
  }

  const files = Array.isArray(args.cookieFile)
    ? args.cookieFile
    : typeof args.cookieFile === 'string'
    ? [args.cookieFile]
    : [];

  for (const filePath of files) {
    if (typeof filePath !== 'string' || filePath.trim() === '') {
      continue;
    }
    const contents = fs.readFileSync(filePath, 'utf8');
    const lines = contents
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line !== '');
    headers.push(...lines);
  }

  return headers;
}

function buildInitialCookies(cookieHeaders, seedUrl) {
  if (!Array.isArray(cookieHeaders) || cookieHeaders.length === 0) {
    return [];
  }
  const baseUrl = `${seedUrl.protocol}//${seedUrl.host}`;
  const jar = new Map();

  for (const header of cookieHeaders) {
    const segments = header.split(';');
    for (const segment of segments) {
      const trimmed = segment.trim();
      if (!trimmed) {
        continue;
      }
      const separator = trimmed.indexOf('=');
      if (separator <= 0) {
        continue;
      }
      const name = trimmed.slice(0, separator).trim();
      const value = trimmed.slice(separator + 1).trim();
      if (!name) {
        continue;
      }
      jar.set(name, value);
    }
  }

  return Array.from(jar.entries()).map(([name, value]) => ({
    name,
    value,
    url: baseUrl,
    path: '/',
  }));
}

async function sleep(ms) {
  if (!Number.isFinite(ms) || ms <= 0) {
    return;
  }
  await new Promise((resolve) => setTimeout(resolve, ms));
}
