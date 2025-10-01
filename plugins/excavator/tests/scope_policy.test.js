const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { loadScopePolicy } = require('../scope_policy');

test('loadScopePolicy parses minimal policy', () => {
  const file = path.join(os.tmpdir(), `scope-${Date.now()}.yaml`);
  fs.writeFileSync(
    file,
    'version: 1\nallow:\n  - type: "domain"\n    value: "example.com"\ndeny:\n  []\nprivate_networks: "block"\npii: "forbid"\n',
    'utf8'
  );
  try {
    const policy = loadScopePolicy(file);
    assert.equal(policy.version, 1);
    assert.equal(policy.allow.length, 1);
    assert.equal(policy.allow[0].type, 'domain');
    assert.equal(policy.allow[0].value, 'example.com');
    assert.ok(Array.isArray(policy.deny));
    assert.equal(policy.deny.length, 0);
    assert.equal(policy.privateNetworks, 'block');
    assert.equal(policy.pii, 'forbid');
  } finally {
    fs.unlinkSync(file);
  }
});
