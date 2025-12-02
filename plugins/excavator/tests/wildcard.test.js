const test = require('node:test');
const assert = require('node:assert/strict');
const { URL } = require('node:url');
const { createScopeChecker } = require('../scope');

test('wildcard pattern with uppercase letters matches correctly', () => {
  const guard = createScopeChecker('custom', {
    seedUrl: new URL('https://api.example.com'),
    seedHost: 'api.example.com',
    seedOrigin: 'https://api.example.com',
    allowlist: [{ type: 'wildcard', value: '*.PROD.example.com' }],
    denylist: [],
  });

  // Should match uppercase PROD
  assert.equal(guard.check('https://api.PROD.example.com/endpoint'), true);
  assert.equal(guard.check('https://api.prod.example.com/endpoint'), true);
  assert.equal(guard.check('https://service.PROD.example.com/endpoint'), true);

  // Should not match different environment
  assert.equal(guard.check('https://api.DEV.example.com/endpoint'), false);
  assert.equal(guard.check('https://api.staging.example.com/endpoint'), false);
});

test('wildcard pattern with mixed case matches case-insensitively', () => {
  const guard = createScopeChecker('custom', {
    seedUrl: new URL('https://example.com'),
    seedHost: 'example.com',
    seedOrigin: 'https://example.com',
    allowlist: [{ type: 'wildcard', value: 'API-*.Example.Com' }],
    denylist: [],
  });

  assert.equal(guard.check('https://api-v1.example.com/data'), true);
  assert.equal(guard.check('https://API-v1.Example.Com/data'), true);
  assert.equal(guard.check('https://api-prod.EXAMPLE.COM/data'), true);

  // Should not match without prefix
  assert.equal(guard.check('https://v1.example.com/data'), false);
});

test('wildcard pattern with special characters escapes correctly', () => {
  const guard = createScopeChecker('custom', {
    seedUrl: new URL('https://example.com'),
    seedHost: 'example.com',
    seedOrigin: 'https://example.com',
    allowlist: [{ type: 'wildcard', value: 'api-v1.*.example.com' }],
    denylist: [],
  });

  // Dot should be literal, not wildcard
  assert.equal(guard.check('https://api-v1.prod.example.com/data'), true);
  assert.equal(guard.check('https://api-v1Xprod.example.com/data'), false);
});

test('wildcard pattern with multiple asterisks', () => {
  const guard = createScopeChecker('custom', {
    seedUrl: new URL('https://example.com'),
    seedHost: 'example.com',
    seedOrigin: 'https://example.com',
    allowlist: [{ type: 'wildcard', value: '*.*.example.com' }],
    denylist: [],
  });

  assert.equal(guard.check('https://api.v1.example.com/path'), true);
  assert.equal(guard.check('https://service.prod.example.com/path'), true);
  assert.equal(guard.check('https://a.b.example.com/path'), true);

  // Should not match single subdomain
  assert.equal(guard.check('https://api.example.com/path'), false);
});

test('wildcard pattern with leading asterisk', () => {
  const guard = createScopeChecker('custom', {
    seedUrl: new URL('https://example.com'),
    seedHost: 'example.com',
    seedOrigin: 'https://example.com',
    allowlist: [{ type: 'wildcard', value: '*.example.com' }],
    denylist: [],
  });

  assert.equal(guard.check('https://api.example.com/path'), true);
  assert.equal(guard.check('https://www.example.com/path'), true);
  assert.equal(guard.check('https://anything.example.com/path'), true);

  // Should not match the base domain
  assert.equal(guard.check('https://example.com/path'), false);
});

test('wildcard pattern with trailing asterisk', () => {
  const guard = createScopeChecker('custom', {
    seedUrl: new URL('https://example.com'),
    seedHost: 'example.com',
    seedOrigin: 'https://example.com',
    allowlist: [{ type: 'wildcard', value: 'api.*' }],
    denylist: [],
  });

  assert.equal(guard.check('https://api.example.com/path'), true);
  assert.equal(guard.check('https://api.test.com/path'), true);
  assert.equal(guard.check('https://api.anything/path'), true);

  assert.equal(guard.check('https://www.example.com/path'), false);
});

test('wildcard pattern exact match (no wildcards)', () => {
  const guard = createScopeChecker('custom', {
    seedUrl: new URL('https://example.com'),
    seedHost: 'example.com',
    seedOrigin: 'https://example.com',
    allowlist: [{ type: 'wildcard', value: 'api.example.com' }],
    denylist: [],
  });

  assert.equal(guard.check('https://api.example.com/path'), true);
  assert.equal(guard.check('https://API.EXAMPLE.COM/path'), true);

  assert.equal(guard.check('https://v1.api.example.com/path'), false);
  assert.equal(guard.check('https://www.example.com/path'), false);
});

test('wildcard pattern with uppercase environment names', () => {
  const guard = createScopeChecker('custom', {
    seedUrl: new URL('https://example.com'),
    seedHost: 'example.com',
    seedOrigin: 'https://example.com',
    allowlist: [
      { type: 'wildcard', value: '*.PROD.example.com' },
      { type: 'wildcard', value: '*.UAT.example.com' },
      { type: 'wildcard', value: '*.QA.example.com' }
    ],
    denylist: [],
  });

  // PROD environment
  assert.equal(guard.check('https://api.PROD.example.com/endpoint'), true);
  assert.equal(guard.check('https://service.prod.example.com/endpoint'), true);

  // UAT environment
  assert.equal(guard.check('https://api.UAT.example.com/endpoint'), true);
  assert.equal(guard.check('https://api.uat.example.com/endpoint'), true);

  // QA environment
  assert.equal(guard.check('https://service.QA.example.com/endpoint'), true);
  assert.equal(guard.check('https://service.qa.example.com/endpoint'), true);

  // DEV should not match
  assert.equal(guard.check('https://api.DEV.example.com/endpoint'), false);
});

test('wildcard pattern with regex special characters gets escaped', () => {
  const guard = createScopeChecker('custom', {
    seedUrl: new URL('https://example.com'),
    seedHost: 'example.com',
    seedOrigin: 'https://example.com',
    allowlist: [{ type: 'wildcard', value: 'api+test.*.example.com' }],
    denylist: [],
  });

  // Plus should be literal, not regex quantifier
  assert.equal(guard.check('https://api+test.v1.example.com/path'), true);
  assert.equal(guard.check('https://apitest.v1.example.com/path'), false);
  assert.equal(guard.check('https://apiitest.v1.example.com/path'), false);
});

test('wildcard pattern empty or invalid patterns', () => {
  const guard = createScopeChecker('custom', {
    seedUrl: new URL('https://example.com'),
    seedHost: 'example.com',
    seedOrigin: 'https://example.com',
    allowlist: [
      { type: 'wildcard', value: '' },
      { type: 'wildcard', value: '   ' },
    ],
    denylist: [],
  });

  // Empty patterns should be ignored, nothing should match
  assert.equal(guard.check('https://api.example.com/path'), false);
});

test('wildcard in denylist blocks matching patterns', () => {
  const guard = createScopeChecker('domain', {
    seedUrl: new URL('https://example.com'),
    seedHost: 'example.com',
    seedOrigin: 'https://example.com',
    allowlist: [{ type: 'domain', value: 'example.com' }],
    denylist: [{ type: 'wildcard', value: '*.INTERNAL.example.com' }],
  });

  assert.equal(guard.check('https://example.com/page'), true);
  assert.equal(guard.check('https://api.example.com/page'), true);

  // Should block internal subdomains
  assert.equal(guard.check('https://service.INTERNAL.example.com/page'), false);
  assert.equal(guard.check('https://api.internal.example.com/page'), false);
});
