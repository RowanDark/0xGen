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

      res.statusCode = 200;
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.end(typeof page === 'function' ? page(requestUrl) : page);
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

test('crawlSite enforces host limits across multiple hosts', async (t) => {
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
  });

  assert.deepStrictEqual(depthZero.meta.allowed_hosts, ['seed.test']);
  assert.ok(depthZero.links.some((link) => new URL(link).hostname === 'alpha.test'));
  assert.ok(depthZero.links.some((link) => new URL(link).hostname === 'beta.test'));
  assert.deepStrictEqual(Object.keys(server.hits()).sort(), ['seed.test']);
});
