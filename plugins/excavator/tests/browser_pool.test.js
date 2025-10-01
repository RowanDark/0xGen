const test = require('node:test');
const assert = require('node:assert/strict');
const { createBrowserPool } = require('../browser_pool');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test('warms and reuses browser contexts', async () => {
  const contexts = [];
  const pool = createBrowserPool({
    size: 1,
    warmup: true,
    createContext: async () => {
      const context = { id: contexts.length + 1, closed: false };
      contexts.push(context);
      return context;
    },
    destroyContext: async (context) => {
      context.closed = true;
    },
  });

  const first = await pool.acquire();
  assert.equal(first.context.id, 1);
  await first.release();

  const second = await pool.acquire();
  assert.equal(second.context.id, 1);
  await second.release();

  await pool.close();
  assert.equal(contexts.length, 1);
  assert.equal(contexts[0].closed, true);
});

test('queues acquire calls until a context is released', async () => {
  let counter = 0;
  const pool = createBrowserPool({
    size: 1,
    warmup: false,
    createContext: async () => ({ id: ++counter }),
  });

  const first = await pool.acquire();
  const seenContext = first.context;
  let secondResolved = false;

  const secondPromise = pool.acquire().then((entry) => {
    secondResolved = true;
    return entry;
  });

  await sleep(20);
  assert.equal(secondResolved, false);

  await first.release();
  const second = await secondPromise;
  assert.strictEqual(second.context, seenContext);
  await second.release();

  await pool.close();
});

test('rotates fingerprints and invokes reset hooks', async () => {
  const applied = [];
  const resets = [];
  const pool = createBrowserPool({
    size: 1,
    warmup: false,
    fingerprints: ['fp1', 'fp2', 'fp3'],
    createContext: async () => ({ id: 1 }),
    applyFingerprint: async (context, fingerprint) => {
      applied.push({ id: context.id, fingerprint });
    },
    resetContext: async (context) => {
      resets.push(context.id);
    },
  });

  const first = await pool.acquire();
  await first.release();
  const second = await pool.acquire();
  await second.release();
  const third = await pool.acquire();
  await third.release();

  await pool.close();

  assert.deepStrictEqual(applied.map((entry) => entry.fingerprint), ['fp1', 'fp2', 'fp3']);
  assert.deepStrictEqual(resets, [1, 1, 1]);
});

test('close rejects pending acquires and blocks new usage', async () => {
  let destroyed = false;
  const pool = createBrowserPool({
    size: 1,
    warmup: false,
    createContext: async () => ({ id: 1 }),
    destroyContext: async () => {
      destroyed = true;
    },
  });

  const first = await pool.acquire();
  const pendingAcquire = pool.acquire();

  const closePromise = pool.close();

  await assert.rejects(pendingAcquire, /closed/);
  await first.release();
  await closePromise;

  assert.equal(destroyed, true);
  await assert.rejects(pool.acquire(), /closed/);
});
