const test = require('node:test');
const assert = require('node:assert/strict');
const { createConcurrencyManager } = require('../concurrency_manager');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test('serialises tasks per host and reuses browser contexts', async () => {
  const contexts = [];
  const resets = [];
  const manager = createConcurrencyManager({
    rateLimiter: {
      perHost: { tokens: 1, intervalMs: 30, burst: 1 },
      globalLimit: 1,
    },
    browserPool: {
      size: 1,
      warmup: false,
      createContext: async () => {
        const context = { id: contexts.length + 1 };
        contexts.push(context);
        return context;
      },
      resetContext: async (context) => {
        resets.push(context.id);
      },
    },
  });

  const starts = [];

  const jobs = Array.from({ length: 3 }, (_, index) =>
    manager.schedule({
      url: `https://crawl.test/${index}`,
      execute: async ({ context }) => {
        starts.push({ index, context: context.id });
        await sleep(20);
        return { status: 200 };
      },
      releaseOptions: { reason: 'success' },
    })
  );

  await Promise.all(jobs);
  await manager.close();

  assert.deepStrictEqual(
    starts.map((entry) => entry.index),
    [0, 1, 2]
  );
  assert.ok(starts.every((entry) => entry.context === 1));
  assert.equal(contexts.length, 1);
  assert.deepStrictEqual(resets, [1, 1, 1]);
});

test('tracks telemetry, handles errors, and supports manual release', async () => {
  const snapshots = [];
  const releases = [];
  const manager = createConcurrencyManager({
    rateLimiter: {
      perHost: { tokens: 1, intervalMs: 20, burst: 1 },
      globalLimit: 1,
      onTelemetry: (snapshot) => {
        snapshots.push(snapshot);
      },
    },
    browserPool: {
      size: 1,
      warmup: false,
      createContext: async () => ({ id: 'alpha' }),
      resetContext: async (_context, options) => {
        releases.push(options);
      },
    },
  });

  await manager.schedule({
    url: 'https://telemetry.test/ok',
    execute: async () => {
      await sleep(10);
      return { status: 200 };
    },
    releaseOptions: { label: 'ok' },
  });

  await manager.schedule({
    url: 'https://telemetry.test/429',
    execute: async () => {
      await sleep(10);
      return { status: 429 };
    },
  });

  await assert.rejects(
    manager.schedule({
      url: 'https://telemetry.test/503',
      execute: async ({ release }) => {
        await sleep(5);
        await release({ label: 'manual' });
        const error = new Error('server error');
        error.status = 503;
        throw error;
      },
      releaseOptions: { label: 'error' },
    })
  );

  const telemetry = manager.getTelemetry();
  await manager.close();

  assert.ok(snapshots.length > 0);
  assert.equal(telemetry.status429, 1);
  assert.equal(telemetry.status5xx, 1);
  assert.ok(telemetry.waitCount >= 1);
  assert.ok(telemetry.avgWaitMs >= 0);

  assert.equal(releases.length, 3);
  assert.deepStrictEqual(releases[0], { label: 'ok' });
  assert.equal(releases[1], undefined);
  assert.deepStrictEqual(releases[2], { label: 'manual' });
});
