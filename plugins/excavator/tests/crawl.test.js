const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { URL } = require('node:url');
const { crawlSite } = require('../crawl');

function nowStub(sequence) {
  let index = 0;
  return () => {
    if (index < sequence.length) {
      return new Date(sequence[index++]);
    }
    return new Date(sequence[sequence.length - 1]);
  };
}

test('crawlSite normalises URLs, respects depth limits, and returns canonical schema', async () => {
  const pages = new Map([
    [
      'https://example.com/',
      {
        url: 'https://example.com/',
        status: 200,
        title: 'Example Home',
        links: ['/#fragment', '/about', 'https://example.com/contact?b=2&a=1', 'https://external.test/path'],
        scripts: [
          { src: '/static/app.js', content: '' },
          { src: '', content: 'console.log("hi");' },
          { src: '/static/app.js', content: '' },
        ],
      },
    ],
    [
      'https://example.com/about',
      {
        url: 'https://example.com/about/',
        status: 200,
        title: 'About',
        links: ['https://example.com/team', 'mailto:security@example.com', 'javascript:void(0)'],
        scripts: [],
      },
    ],
    [
      'https://example.com/contact?a=1&b=2',
      {
        url: 'https://example.com/contact?a=1&b=2',
        status: 200,
        title: 'Contact',
        links: [],
        scripts: [],
      },
    ],
  ]);

  const fetchPage = async (url) => {
    const normalised = url.endsWith('/') ? url : `${url}`;
    const entry =
      pages.get(normalised) ||
      pages.get(`${normalised}/`) ||
      pages.get(normalised.replace(/\/+$/, ''));
    if (!entry) {
      throw new Error(`unexpected fetch for ${url}`);
    }
    return entry;
  };

  const result = await crawlSite({
    seed: 'https://example.com',
    depth: 1,
    hostLimit: 1,
    fetchPage,
    now: nowStub(['2024-01-01T00:00:00Z', '2024-01-01T00:00:05Z']),
    scope: 'origin',
  });

  assert.deepStrictEqual(Object.keys(result).sort(), ['links', 'meta', 'scripts', 'target']);
  assert.equal(result.target, 'https://example.com');

  assert.ok(Array.isArray(result.links));
  assert.deepStrictEqual(result.links, [
    'https://example.com',
    'https://example.com/about',
    'https://example.com/contact?a=1&b=2',
    'https://example.com/team',
  ]);
  assert.ok(!result.links.includes('https://external.test/path'));

  assert.ok(Array.isArray(result.scripts));
  assert.deepStrictEqual(result.scripts, [
    { src: null, snippet: 'console.log("hi");' },
    { src: 'https://example.com/static/app.js', snippet: '' },
  ]);

  assert.ok(result.meta);
  assert.deepStrictEqual(Object.keys(result.meta).sort(), ['allowed_hosts', 'crawled_at', 'depth']);
  assert.equal(result.meta.depth, 1);
  assert.equal(result.meta.crawled_at, '2024-01-01T00:00:05.000Z');
  assert.deepStrictEqual(result.meta.allowed_hosts, ['example.com']);
});

function startTestServer(routeFactory) {
  return new Promise((resolve, reject) => {
    const hits = new Map();
    let routes = {};

    const server = http.createServer((req, res) => {
      const hostHeader = req.headers.host || '';
      const hostName = hostHeader.split(':')[0].toLowerCase();
      const requestUrl = new URL(req.url, `http://${hostHeader || '127.0.0.1'}`);
      hits.set(hostName, (hits.get(hostName) || 0) + 1);

      const hostRoutes = routes[hostName];
      const page = hostRoutes && hostRoutes[requestUrl.pathname];
      if (!page) {
        res.statusCode = 404;
        res.end(`no route for ${hostName}${requestUrl.pathname}`);
        return;
      }

      const payload = typeof page === 'function' ? page(requestUrl, req) : page;
      const { body, headers, statusCode } = normaliseResponse(payload);

      res.statusCode = statusCode;
      for (const [headerName, headerValue] of Object.entries(headers)) {
        res.setHeader(headerName, headerValue);
      }
      res.end(body);
    });

    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      routes = routeFactory(address.port);
      resolve({
        port: address.port,
        async close() {
          await new Promise((res, rej) => {
            server.close((err) => {
              if (err) {
                rej(err);
                return;
              }
              res();
            });
          });
        },
        resetHits() {
          hits.clear();
        },
        hits() {
          return Object.fromEntries(hits);
        },
      });
    });
  });
}

function normaliseResponse(value) {
  if (value && typeof value === 'object' && !Buffer.isBuffer(value) && 'body' in value) {
    const headers = Object.assign({ 'content-type': 'text/html; charset=utf-8' }, value.headers || {});
    const statusCode = typeof value.statusCode === 'number' ? value.statusCode : 200;
    return { body: value.body || '', headers, statusCode };
  }
  return {
    body: typeof value === 'string' || Buffer.isBuffer(value) ? value : String(value ?? ''),
    headers: { 'content-type': 'text/html; charset=utf-8' },
    statusCode: 200,
  };
}

function extractLinks(html) {
  const links = [];
  const pattern = /<a[^>]*href\s*=\s*(['"])(.*?)\1/gi;
  let match;
  while ((match = pattern.exec(html)) !== null) {
    links.push(match[2]);
  }
  return links;
}

function createFetcher(defaultPort) {
  return async function fetchPage(url) {
    const target = new URL(url);
    const port = target.port ? Number.parseInt(target.port, 10) : defaultPort;
    const options = {
      protocol: target.protocol,
      hostname: '127.0.0.1',
      port,
      path: `${target.pathname}${target.search}`,
      method: 'GET',
      headers: {
        Host: target.host,
      },
      lookup(hostname, _options, callback) {
        callback(null, '127.0.0.1', 4);
      },
    };

    const responseData = await new Promise((resolve, reject) => {
      const request = http.request(options, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          resolve({
            statusCode: response.statusCode || 0,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      });
      request.on('error', reject);
      request.end();
    });

    return {
      url,
      status: responseData.statusCode,
      title: '',
      links: extractLinks(responseData.body),
      scripts: [],
    };
  };
}

function htmlPage(title, hrefs) {
  const links = hrefs
    .map((href, index) => `<a id="link-${index}" href="${href}">Link ${index}</a>`)
    .join('');
  return `<!DOCTYPE html><html><head><title>${title}</title></head><body>${links}</body></html>`;
}

test('crawlSite enforces host limits across multiple hosts with a custom scope', async (t) => {
  const server = await startTestServer((port) => ({
    'seed.test': {
      '/': htmlPage('Seed Root', [
        '/about',
        `http://alpha.test:${port}/alpha`,
        `http://beta.test:${port}/beta`,
        `http://gamma.test:${port}/gamma`,
      ]),
      '/about': htmlPage('About', ['/deep']),
      '/deep': htmlPage('Deep', []),
    },
    'alpha.test': {
      '/alpha': htmlPage('Alpha', [`http://beta.test:${port}/beta`]),
    },
    'beta.test': {
      '/beta': htmlPage('Beta', [`http://gamma.test:${port}/gamma`]),
    },
    'gamma.test': {
      '/gamma': htmlPage('Gamma', []),
    },
  }));

  t.after(async () => {
    await server.close();
  });

  const fetchPage = createFetcher(server.port);
  const seed = `http://seed.test:${server.port}/`;

  server.resetHits();
  const singleHost = await crawlSite({
    seed,
    depth: 2,
    hostLimit: 1,
    fetchPage,
    now: nowStub(['2024-01-01T00:00:00Z', '2024-01-01T00:00:01Z']),
    scope: 'custom',
    scopeAllowlist: [`^http://seed.test:${server.port}/`],
  });

  assert.deepStrictEqual(singleHost.meta.allowed_hosts, ['seed.test']);
  assert.ok(singleHost.links.every((link) => new URL(link).hostname === 'seed.test'));
  assert.deepStrictEqual(Object.keys(server.hits()).sort(), ['seed.test']);

  server.resetHits();
  const multiHost = await crawlSite({
    seed,
    depth: 2,
    hostLimit: 3,
    fetchPage,
    now: nowStub(['2024-01-02T00:00:00Z', '2024-01-02T00:00:01Z']),
    scope: 'custom',
    scopeAllowlist: [
      `^http://seed.test:${server.port}/`,
      `^http://alpha.test:${server.port}/`,
      `^http://beta.test:${server.port}/`,
      `^http://gamma.test:${server.port}/`,
    ],
  });

  assert.deepStrictEqual(multiHost.meta.allowed_hosts, ['alpha.test', 'beta.test', 'seed.test']);
  const multiHostHits = Object.keys(server.hits()).sort();
  assert.deepStrictEqual(multiHostHits, ['alpha.test', 'beta.test', 'seed.test']);
  assert.ok(multiHost.links.some((link) => new URL(link).hostname === 'alpha.test'));
  assert.ok(multiHost.links.some((link) => new URL(link).hostname === 'beta.test'));
  assert.ok(!multiHost.links.some((link) => new URL(link).hostname === 'gamma.test'));

  server.resetHits();
  const depthZero = await crawlSite({
    seed,
    depth: 0,
    hostLimit: 3,
    fetchPage,
    now: nowStub(['2024-01-03T00:00:00Z', '2024-01-03T00:00:01Z']),
    scope: 'custom',
    scopeAllowlist: [
      `^http://seed.test:${server.port}/`,
      `^http://alpha.test:${server.port}/`,
      `^http://beta.test:${server.port}/`,
      `^http://gamma.test:${server.port}/`,
    ],
  });

  assert.deepStrictEqual(depthZero.meta.allowed_hosts, ['seed.test']);
  assert.ok(depthZero.links.some((link) => new URL(link).hostname === 'alpha.test'));
  assert.ok(depthZero.links.some((link) => new URL(link).hostname === 'beta.test'));
  assert.deepStrictEqual(Object.keys(server.hits()).sort(), ['seed.test']);
});

test('crawlSite retains cookies, enforces scope, and honours delay/max page limits', async (t) => {
  const seenCookies = [];
  let outsideHits = 0;

  const server = await startTestServer((port) => ({
    'origin.test': {
      '/': () => ({
        headers: {
          'Set-Cookie': ['session=alpha; Path=/', 'pref=blue; Path=/'],
        },
        body: htmlPage('Origin Root', [`/next`, `http://other.test:${port}/outside`]),
      }),
      '/next': (_url, req) => {
        seenCookies.push(req.headers.cookie || '');
        return htmlPage('Next', [`http://allowed.test:${port}/allowed`]);
      },
    },
    'other.test': {
      '/outside': () => {
        outsideHits += 1;
        return htmlPage('Outside', []);
      },
    },
    'allowed.test': {
      '/allowed': () => htmlPage('Allowed', []),
    },
  }));

  t.after(async () => {
    await server.close();
  });

  const fetchPage = createCookieFetcher(server.port);
  const seed = `http://origin.test:${server.port}/`;

  const waitDurations = [];

  const result = await crawlSite({
    seed,
    depth: 3,
    hostLimit: 4,
    fetchPage,
    now: nowStub(['2024-01-04T00:00:00Z', '2024-01-04T00:00:02Z']),
    scope: 'custom',
    scopeAllowlist: [
      `^http://origin.test:${server.port}/`,
      `^http://allowed.test:${server.port}/`,
    ],
    delayMs: 15,
    maxPages: 2,
    wait: (ms) => {
      waitDurations.push(ms);
      return Promise.resolve();
    },
  });

  assert.deepStrictEqual(result.meta.allowed_hosts.sort(), ['allowed.test', 'origin.test']);
  assert.strictEqual(outsideHits, 0);
  assert.ok(seenCookies.some((cookieHeader) => cookieHeader.includes('session=alpha')));
  assert.ok(seenCookies.some((cookieHeader) => cookieHeader.includes('pref=blue')));
  assert.deepStrictEqual(waitDurations, [15]);
  assert.ok(result.links.every((link) => /origin\.test|allowed\.test/.test(new URL(link).hostname)));
});

function createCookieFetcher(defaultPort) {
  const cookieStores = new Map();

  return async function fetchPage(url) {
    const target = new URL(url);
    const port = target.port ? Number.parseInt(target.port, 10) : defaultPort;
    const originKey = `${target.protocol}//${target.host}`;
    const cookieEntries = cookieStores.get(originKey);
    const cookieHeader = cookieEntries
      ? Array.from(cookieEntries.entries())
          .map(([name, value]) => `${name}=${value}`)
          .join('; ')
      : '';

    const options = {
      protocol: target.protocol,
      hostname: '127.0.0.1',
      port,
      path: `${target.pathname}${target.search}`,
      method: 'GET',
      headers: {
        Host: target.host,
      },
      lookup(hostname, _options, callback) {
        callback(null, '127.0.0.1', 4);
      },
    };

    if (cookieHeader) {
      options.headers.Cookie = cookieHeader;
    }

    const responseData = await new Promise((resolve, reject) => {
      const request = http.request(options, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const setCookie = response.headers['set-cookie'];
          const incomingCookies = Array.isArray(setCookie)
            ? setCookie
            : setCookie
            ? [setCookie]
            : [];
          if (incomingCookies.length > 0) {
            const jar = cookieStores.get(originKey) || new Map();
            for (const cookieLine of incomingCookies) {
              const [pair] = cookieLine.split(';', 1);
              if (!pair) {
                continue;
              }
              const separator = pair.indexOf('=');
              if (separator <= 0) {
                continue;
              }
              const name = pair.slice(0, separator).trim();
              const value = pair.slice(separator + 1).trim();
              if (!name) {
                continue;
              }
              jar.set(name, value);
            }
            cookieStores.set(originKey, jar);
          }

          resolve({
            statusCode: response.statusCode || 0,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      });
      request.on('error', reject);
      request.end();
    });

    return {
      url,
      status: responseData.statusCode,
      title: '',
      links: extractLinks(responseData.body),
      scripts: [],
    };
  };
}
