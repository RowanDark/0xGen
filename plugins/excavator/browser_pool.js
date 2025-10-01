'use strict';

function createBrowserPool(options = {}) {
  const {
    size = 2,
    createContext,
    destroyContext,
    applyFingerprint,
    resetContext,
    fingerprints = [],
    warmup = true,
  } = options;

  if (typeof createContext !== 'function') {
    throw new Error('createContext function is required');
  }

  const capacity = Math.max(1, Math.floor(size));
  const pending = [];
  const available = [];
  const resources = new Set();
  const inUse = new Set();
  const creationPromises = new Set();
  let creating = 0;
  let closing = false;
  let closed = false;
  let fingerprintIndex = 0;

  function selectFingerprint() {
    if (!Array.isArray(fingerprints) || fingerprints.length === 0) {
      return null;
    }
    const index = fingerprintIndex % fingerprints.length;
    fingerprintIndex += 1;
    return fingerprints[index];
  }

  function ensureCapacity() {
    if (closing || closed) {
      return;
    }

    const existing = resources.size;
    const totalWithCreating = existing + creating;
    const demand = pending.length;
    const idle = available.length;
    const deficitDemand = Math.max(0, demand - idle);

    let desiredTotal;
    if (warmup) {
      desiredTotal = capacity;
    } else {
      desiredTotal = Math.min(capacity, existing + deficitDemand);
      if (desiredTotal === 0 && demand > 0) {
        desiredTotal = Math.min(capacity, demand);
      }
    }

    const deficit = Math.max(0, desiredTotal - totalWithCreating);
    for (let i = 0; i < deficit; i += 1) {
      spawnContext();
    }
  }

  async function destroyResource(resource) {
    if (!resource || resource.destroyed) {
      if (resource && typeof resource.resolveClosed === 'function') {
        resource.resolveClosed();
      }
      return;
    }
    resource.destroyed = true;
    resources.delete(resource);
    try {
      if (typeof destroyContext === 'function') {
        await destroyContext(resource.context);
      } else if (resource.context && typeof resource.context.close === 'function') {
        await resource.context.close();
      }
    } finally {
      if (typeof resource.resolveClosed === 'function') {
        resource.resolveClosed();
      }
    }
  }

  function dispatch() {
    if (closing || closed) {
      return;
    }

    while (pending.length > 0 && available.length > 0) {
      const request = pending.shift();
      const resource = available.shift();
      inUse.add(resource);
      const fingerprint = selectFingerprint();

      Promise.resolve()
        .then(() => {
          if (fingerprint && typeof applyFingerprint === 'function') {
            return applyFingerprint(resource.context, fingerprint);
          }
          return undefined;
        })
        .then(() => {
          resource.released = false;
          request.resolve({
            context: resource.context,
            fingerprint,
            release: (options) => release(resource, options),
          });
        })
        .catch(async (error) => {
          inUse.delete(resource);
          await destroyResource(resource);
          ensureCapacity();
          request.reject(error);
        });
    }

    ensureCapacity();
  }

  function release(resource, options) {
    if (!resource || resource.released) {
      return Promise.resolve();
    }
    resource.released = true;
    inUse.delete(resource);

    const performReset = () => {
      if (typeof resetContext === 'function') {
        return resetContext(resource.context, options);
      }
      return Promise.resolve();
    };

    return Promise.resolve()
      .then(() => performReset())
      .then(async () => {
        if (closing || closed) {
          await destroyResource(resource);
          return;
        }
        resource.released = false;
        available.push(resource);
        dispatch();
      })
      .catch(async (error) => {
        await destroyResource(resource);
        ensureCapacity();
        throw error;
      });
  }

  function spawnContext() {
    creating += 1;
    const creation = Promise.resolve()
      .then(() => createContext())
      .then((context) => {
        if (closing || closed) {
          if (typeof destroyContext === 'function') {
            return destroyContext(context);
          }
          if (context && typeof context.close === 'function') {
            return context.close();
          }
          return undefined;
        }

        const resource = {
          context,
          released: false,
          destroyed: false,
        };
        resource.closedPromise = new Promise((resolve) => {
          resource.resolveClosed = resolve;
        });
        resources.add(resource);
        available.push(resource);
        dispatch();
        return undefined;
      })
      .catch((error) => {
        if (pending.length > 0) {
          const request = pending.shift();
          request.reject(error);
        }
      })
      .finally(() => {
        creating = Math.max(0, creating - 1);
        creationPromises.delete(creation);
      });
    creationPromises.add(creation);
  }

  function acquire() {
    if (closing || closed) {
      return Promise.reject(new Error('browser pool is closed'));
    }
    return new Promise((resolve, reject) => {
      const request = { resolve, reject };
      pending.push(request);
      dispatch();
    });
  }

  async function close() {
    if (closed) {
      return;
    }
    closing = true;

    while (pending.length > 0) {
      const request = pending.shift();
      request.reject(new Error('browser pool is closed'));
    }

    if (creationPromises.size > 0) {
      await Promise.all(Array.from(creationPromises));
    }

    const destruction = [];
    for (const resource of Array.from(resources)) {
      if (!inUse.has(resource)) {
        destruction.push(destroyResource(resource));
      }
    }
    await Promise.all(destruction);

    if (inUse.size > 0) {
      await Promise.all(Array.from(inUse, (resource) => resource.closedPromise));
    }

    closed = true;
  }

  if (warmup) {
    ensureCapacity();
  }

  return {
    acquire,
    close,
  };
}

module.exports = { createBrowserPool };
