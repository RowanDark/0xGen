'use strict';

const { URL } = require('node:url');

function createRateLimitedQueue(options = {}) {
  const {
    perHost = {},
    globalLimit = 5,
    minBackoffMs = 1000,
    maxBackoffMs = 30000,
    backoffMultiplier = 2,
    now = () => Date.now(),
    setTimeoutFn = (fn, ms) => setTimeout(fn, ms),
    clearTimeoutFn = (id) => clearTimeout(id),
    onTelemetry,
  } = options;

  const tokensPerInterval = Number(perHost.tokens);
  if (!Number.isFinite(tokensPerInterval) || tokensPerInterval <= 0) {
    throw new Error('perHost.tokens must be a positive number');
  }

  const intervalMsRaw = Number(perHost.intervalMs);
  if (!Number.isFinite(intervalMsRaw) || intervalMsRaw <= 0) {
    throw new Error('perHost.intervalMs must be a positive number of milliseconds');
  }

  const burstRaw = Number(perHost.burst);
  const bucketCapacity =
    Number.isFinite(burstRaw) && burstRaw > 0 ? burstRaw : Math.max(tokensPerInterval, 1);

  const tokensPerMs = tokensPerInterval / intervalMsRaw;

  const globalCap = Number.isFinite(globalLimit) && globalLimit > 0 ? Math.floor(globalLimit) : Infinity;
  if (!Number.isFinite(globalCap) || globalCap <= 0) {
    throw new Error('globalLimit must be a positive number');
  }

  const minBackoff = Number(minBackoffMs);
  if (!Number.isFinite(minBackoff) || minBackoff < 0) {
    throw new Error('minBackoffMs must be a non-negative number');
  }

  const maxBackoff = Number(maxBackoffMs);
  if (!Number.isFinite(maxBackoff) || maxBackoff < 0) {
    throw new Error('maxBackoffMs must be a non-negative number');
  }

  const multiplier = Number(backoffMultiplier);
  if (!Number.isFinite(multiplier) || multiplier <= 0) {
    throw new Error('backoffMultiplier must be a positive number');
  }

  const queue = [];
  const hostStates = new Map();
  let active = 0;
  let processing = false;
  let scheduledTimer = null;
  let closed = false;

  const telemetry = {
    wait: { totalMs: 0, count: 0, maxMs: 0 },
    status429: 0,
    status5xx: 0,
    maxQueueDepth: 0,
  };

  function emitTelemetry() {
    if (typeof onTelemetry === 'function') {
      onTelemetry(getTelemetrySnapshot());
    }
  }

  function updateQueueDepth() {
    telemetry.maxQueueDepth = Math.max(telemetry.maxQueueDepth, queue.length);
    emitTelemetry();
  }

  function recordWait(durationMs) {
    if (!Number.isFinite(durationMs) || durationMs < 0) {
      return;
    }
    telemetry.wait.totalMs += durationMs;
    telemetry.wait.count += 1;
    telemetry.wait.maxMs = Math.max(telemetry.wait.maxMs, durationMs);
    emitTelemetry();
  }

  function getTelemetrySnapshot() {
    const average =
      telemetry.wait.count > 0 ? telemetry.wait.totalMs / telemetry.wait.count : 0;
    return {
      queueDepth: queue.length,
      maxQueueDepth: telemetry.maxQueueDepth,
      avgWaitMs: average,
      maxWaitMs: telemetry.wait.maxMs,
      waitCount: telemetry.wait.count,
      status429: telemetry.status429,
      status5xx: telemetry.status5xx,
    };
  }

  function extractHost(task) {
    if (task && typeof task.host === 'string' && task.host.trim() !== '') {
      return task.host.trim().toLowerCase();
    }
    if (task && typeof task.url === 'string' && task.url.trim() !== '') {
      try {
        return new URL(task.url).hostname.toLowerCase();
      } catch (error) {
        return null;
      }
    }
    return null;
  }

  function getHostState(host, timestamp) {
    let state = hostStates.get(host);
    if (!state) {
      state = {
        tokens: bucketCapacity,
        lastRefill: timestamp,
        backoffUntil: 0,
        backoffLevel: 0,
      };
      hostStates.set(host, state);
      return state;
    }
    refillTokens(state, timestamp);
    return state;
  }

  function refillTokens(state, timestamp) {
    if (tokensPerMs <= 0) {
      state.tokens = bucketCapacity;
      state.lastRefill = timestamp;
      return;
    }
    const elapsed = Math.max(0, timestamp - state.lastRefill);
    if (elapsed <= 0) {
      return;
    }
    state.tokens = Math.min(bucketCapacity, state.tokens + elapsed * tokensPerMs);
    state.lastRefill = timestamp;
  }

  function timeUntilNextToken(state) {
    if (tokensPerMs <= 0) {
      return 0;
    }
    if (state.tokens >= 1) {
      return 0;
    }
    const deficit = 1 - state.tokens;
    return Math.ceil(deficit / tokensPerMs);
  }

  function applyBackoff(state, timestamp) {
    if (minBackoff <= 0 && maxBackoff <= 0) {
      state.backoffUntil = 0;
      return;
    }
    state.backoffLevel = Math.min(state.backoffLevel + 1, 32);
    const effectiveMin = Math.max(minBackoff, 0);
    const exponent = Math.max(0, state.backoffLevel - 1);
    const calculated = effectiveMin * Math.pow(multiplier, exponent);
    const delay = maxBackoff > 0 ? Math.min(maxBackoff, calculated || effectiveMin) : calculated || effectiveMin;
    state.backoffUntil = timestamp + delay;
  }

  function resetBackoff(state) {
    state.backoffLevel = 0;
    state.backoffUntil = 0;
  }

  function getStatus(result, error) {
    if (error) {
      if (typeof error.status === 'number') {
        return error.status;
      }
      if (typeof error.statusCode === 'number') {
        return error.statusCode;
      }
      return 500;
    }
    if (typeof result === 'number') {
      return result;
    }
    if (result && typeof result.status === 'number') {
      return result.status;
    }
    if (result && typeof result.statusCode === 'number') {
      return result.statusCode;
    }
    return undefined;
  }

  function scheduleNext(delayMs) {
    if (scheduledTimer) {
      clearTimeoutFn(scheduledTimer);
      scheduledTimer = null;
    }
    if (queue.length === 0 || closed) {
      return;
    }
    const delay = Math.max(1, Math.ceil(delayMs));
    scheduledTimer = setTimeoutFn(() => {
      scheduledTimer = null;
      processQueue();
    }, delay);
  }

  function finalize(entry, hostState, error, result) {
    active = Math.max(0, active - 1);

    const status = getStatus(result, error);
    const nowTs = now();

    if (status === 429) {
      telemetry.status429 += 1;
      applyBackoff(hostState, nowTs);
    } else if (typeof status === 'number' && status >= 500 && status < 600) {
      telemetry.status5xx += 1;
      applyBackoff(hostState, nowTs);
    } else if (!error) {
      resetBackoff(hostState);
    }

    if (error) {
      entry.reject(error);
    } else {
      entry.resolve(result);
    }

    emitTelemetry();
    processQueue();
  }

  function processQueue() {
    if (processing || closed) {
      return;
    }
    processing = true;

    if (scheduledTimer) {
      clearTimeoutFn(scheduledTimer);
      scheduledTimer = null;
    }

    try {
      let nextDelay = null;
      let nowTs = now();

      for (let i = 0; i < queue.length; i += 1) {
        if (active >= globalCap) {
          break;
        }

        const entry = queue[i];
        const hostState = getHostState(entry.host, nowTs);

        if (hostState.backoffUntil > nowTs) {
          const waitBackoff = hostState.backoffUntil - nowTs;
          nextDelay = nextDelay === null ? waitBackoff : Math.min(nextDelay, waitBackoff);
          continue;
        }

        refillTokens(hostState, nowTs);
        if (hostState.tokens < 1) {
          const waitForTokens = timeUntilNextToken(hostState);
          nextDelay = nextDelay === null ? waitForTokens : Math.min(nextDelay, waitForTokens);
          continue;
        }

        queue.splice(i, 1);
        i -= 1;
        hostState.tokens = Math.max(0, hostState.tokens - 1);
        active += 1;
        updateQueueDepth();

        const startTs = now();
        recordWait(startTs - entry.enqueuedAt);

        Promise.resolve()
          .then(() => entry.run(entry.task))
          .then((result) => finalize(entry, hostState, null, result))
          .catch((error) => finalize(entry, hostState, error, null));

        nowTs = now();
      }

      if (queue.length > 0 && !closed) {
        if (nextDelay === null) {
          nextDelay = Math.max(intervalMsRaw, 10);
        }
        scheduleNext(nextDelay);
      }
    } finally {
      processing = false;
    }
  }

  function enqueue(task) {
    if (closed) {
      return Promise.reject(new Error('rate-limited queue is closed'));
    }
    if (!task || typeof task.run !== 'function') {
      return Promise.reject(new Error('task.run must be a function'));
    }
    const host = extractHost(task);
    if (!host) {
      return Promise.reject(new Error('task.host or task.url must provide a valid host'));
    }

    return new Promise((resolve, reject) => {
      const entry = {
        host,
        task,
        run: task.run,
        resolve,
        reject,
        enqueuedAt: now(),
      };
      queue.push(entry);
      updateQueueDepth();
      processQueue();
    });
  }

  function size() {
    return queue.length;
  }

  function activeCount() {
    return active;
  }

  async function close() {
    if (closed) {
      return;
    }
    closed = true;
    if (scheduledTimer) {
      clearTimeoutFn(scheduledTimer);
      scheduledTimer = null;
    }
    while (queue.length > 0) {
      const entry = queue.shift();
      entry.reject(new Error('rate-limited queue is closed'));
    }
  }

  return {
    enqueue,
    size,
    activeCount,
    close,
    getTelemetry: getTelemetrySnapshot,
  };
}

module.exports = { createRateLimitedQueue };
