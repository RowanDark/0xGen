const test = require('node:test');
const assert = require('node:assert/strict');
const { createRateLimitedQueue } = require('../queue_manager');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test('enforces per-host token bucket sequencing', async () => {
  const queue = createRateLimitedQueue({
    perHost: { tokens: 1, intervalMs: 40, burst: 1 },
    globalLimit: 4,
  });

  const starts = [];
  let active = 0;
  const tasks = [];

  for (let i = 0; i < 3; i += 1) {
    tasks.push(
      queue.enqueue({
        url: `https://rate.test/page-${i}`,
        run: async () => {
          active += 1;
          starts.push({ index: i, active });
          await sleep(20);
          active -= 1;
          return { status: 200 };
        },
      })
    );
  }

  await Promise.all(tasks);
  await queue.close();

  assert.deepStrictEqual(
    starts.map((entry) => entry.index),
    [0, 1, 2]
  );
  assert.ok(starts.every((entry) => entry.active === 1));
});

test('respects global concurrency limits across hosts', async () => {
  const queue = createRateLimitedQueue({
    perHost: { tokens: 5, intervalMs: 20, burst: 5 },
    globalLimit: 1,
  });

  let concurrent = 0;
  const observed = [];
  const hosts = ['a.test', 'b.test', 'c.test'];

  const tasks = hosts.map((host) =>
    queue.enqueue({
      host,
      url: `https://${host}/resource`,
      run: async () => {
        concurrent += 1;
        observed.push(concurrent);
        await sleep(15);
        concurrent -= 1;
        return { status: 200 };
      },
    })
  );

  await Promise.all(tasks);
  await queue.close();

  assert.ok(observed.length >= hosts.length);
  assert.ok(observed.every((value) => value === 1));
});

test('applies backoff after 429 responses', async () => {
  const minBackoff = 40;
  const queue = createRateLimitedQueue({
    perHost: { tokens: 5, intervalMs: 10, burst: 5 },
    globalLimit: 1,
    minBackoffMs: minBackoff,
    maxBackoffMs: 250,
  });

  let firstEnd = 0;
  let secondStart = 0;

  const first = queue.enqueue({
    url: 'https://limit.test/start',
    run: async () => {
      await sleep(20);
      firstEnd = Date.now();
      return { status: 429 };
    },
  });

  const second = queue.enqueue({
    url: 'https://limit.test/next',
    run: async () => {
      secondStart = Date.now();
      await sleep(5);
      return { status: 200 };
    },
  });

  await Promise.all([first, second]);
  await queue.close();

  assert.ok(secondStart - firstEnd >= minBackoff - 5);
});

test('reports telemetry for waits and status codes', async () => {
  const snapshots = [];
  const queue = createRateLimitedQueue({
    perHost: { tokens: 1, intervalMs: 30, burst: 1 },
    globalLimit: 1,
    minBackoffMs: 30,
    maxBackoffMs: 60,
    onTelemetry: (snapshot) => {
      snapshots.push(snapshot);
    },
  });

  const jobs = [
    queue.enqueue({
      url: 'https://telemetry.test/1',
      run: async () => {
        await sleep(10);
        return { status: 200 };
      },
    }),
    queue.enqueue({
      url: 'https://telemetry.test/2',
      run: async () => {
        await sleep(10);
        return { status: 429 };
      },
    }),
    queue.enqueue({
      url: 'https://telemetry.test/3',
      run: async () => {
        await sleep(10);
        return { status: 503 };
      },
    }),
  ];

  await Promise.all(jobs);
  const telemetry = queue.getTelemetry();
  await queue.close();

  assert.ok(telemetry.maxQueueDepth >= 2);
  assert.ok(telemetry.avgWaitMs > 0);
  assert.equal(telemetry.status429, 1);
  assert.equal(telemetry.status5xx, 1);
  assert.ok(snapshots.some((snapshot) => snapshot.queueDepth >= 2));
});
