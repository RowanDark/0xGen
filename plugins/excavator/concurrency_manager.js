'use strict';

const { createRateLimitedQueue } = require('./queue_manager');
const { createBrowserPool } = require('./browser_pool');

function createConcurrencyManager(options = {}) {
  const {
    rateLimiter = {
      perHost: { tokens: 1, intervalMs: 1000, burst: 1 },
      globalLimit: 1,
    },
    browserPool: browserPoolOptions = {},
  } = options;

  const queue = createRateLimitedQueue(rateLimiter);
  const pool = createBrowserPool(browserPoolOptions);

  let closing = false;
  let closed = false;

  async function runWithBrowser(task) {
    const resource = await pool.acquire();
    let released = false;
    let result;
    let runError;
    let releaseError;

    const release = async (releaseOptions) => {
      if (released) {
        return;
      }
      released = true;
      await resource.release(releaseOptions);
    };

    try {
      result = await task.execute({
        context: resource.context,
        fingerprint: resource.fingerprint,
        release,
      });
    } catch (error) {
      runError = error;
    }

    if (!released) {
      try {
        const releaseOptions = await resolveReleaseOptions(task, result, runError);
        await release(releaseOptions);
      } catch (error) {
        releaseError = error;
      }
    }

    if (runError) {
      throw runError;
    }
    if (releaseError) {
      throw releaseError;
    }
    return result;
  }

  function schedule(task) {
    if (closing || closed) {
      return Promise.reject(new Error('concurrency manager is closed'));
    }
    validateTask(task);

    return queue.enqueue({
      host: task.host,
      url: task.url,
      run: () => runWithBrowser(task),
    });
  }

  async function close() {
    if (closed) {
      return;
    }
    closing = true;

    let queueError = null;
    try {
      await queue.close();
    } catch (error) {
      queueError = error;
    }

    let poolError = null;
    try {
      await pool.close();
    } catch (error) {
      poolError = error;
    }

    closed = true;
    closing = false;

    if (queueError) {
      throw queueError;
    }
    if (poolError) {
      throw poolError;
    }
  }

  function getTelemetry() {
    return queue.getTelemetry();
  }

  return {
    schedule,
    close,
    getTelemetry,
  };
}

function validateTask(task) {
  if (!task || typeof task !== 'object') {
    throw new Error('task must be an object');
  }
  if (typeof task.execute !== 'function') {
    throw new Error('task.execute must be a function');
  }

  const hasHost = typeof task.host === 'string' && task.host.trim() !== '';
  const hasUrl = typeof task.url === 'string' && task.url.trim() !== '';

  if (!hasHost && !hasUrl) {
    throw new Error('task.url or task.host must be provided');
  }
}

async function resolveReleaseOptions(task, result, error) {
  const { releaseOptions } = task;

  if (typeof releaseOptions === 'function') {
    return releaseOptions({ result, error });
  }

  return releaseOptions;
}

module.exports = { createConcurrencyManager };
