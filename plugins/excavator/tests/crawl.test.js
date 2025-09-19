const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

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

test('crawlSite normalises URLs, respects depth limits, and de-dupes links', async () => {
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
    maxDepth: 1,
    maxPages: 5,
    allowedHosts: ['example.com', 'cdn.example.com'],
    fetchPage,
    now: nowStub(['2024-01-01T00:00:00Z', '2024-01-01T00:00:05Z']),
  });

  const goldenPath = path.join(__dirname, 'crawl.golden.json');
  const expected = JSON.parse(fs.readFileSync(goldenPath, 'utf8'));

  assert.deepStrictEqual(result, expected);
});
