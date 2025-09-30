'use strict';

const net = require('node:net');
const { URL } = require('node:url');

function defaultLogger(entry) {
  if (!entry) {
    return;
  }
  try {
    console.warn(JSON.stringify(Object.assign({ level: 'warn' }, entry)));
  } catch (error) {
    console.warn('[scope_violation]', entry.reason || 'unknown', entry.url || '');
  }
}

function createScopeChecker(mode, context = {}) {
  const normalisedMode = typeof mode === 'string' ? mode.toLowerCase() : 'origin';
  const {
    seedUrl,
    seedHost,
    seedOrigin,
    allowlist = [],
    unsafeFollow = false,
    allowPrivate = false,
    allowedProtocols,
    logger = defaultLogger,
  } = context;

  const seedDomain = deriveRegistrableDomain(seedHost);
  const allowPatterns = Array.isArray(allowlist)
    ? allowlist
        .map((pattern) => {
          if (typeof pattern !== 'string' || pattern.trim() === '') {
            return null;
          }
          try {
            return { pattern, expression: new RegExp(pattern) };
          } catch (error) {
            logger({
              type: 'scope_violation',
              reason: 'invalid_allowlist_pattern',
              url: seedUrl ? seedUrl.toString() : '',
              details: { pattern, error: error.message },
            });
            return null;
          }
        })
        .filter(Boolean)
    : [];

  const protocolList = Array.isArray(allowedProtocols) && allowedProtocols.length > 0
    ? allowedProtocols
        .map((value) => (typeof value === 'string' ? value.trim().toLowerCase() : ''))
        .filter((value) => value !== '')
    : ['http', 'https'];

  const protocolSet = new Set(protocolList);

  function logViolation(url, reason, meta) {
    if (typeof logger !== 'function') {
      return;
    }
    const details = meta && typeof meta === 'object' ? Object.assign({}, meta) : undefined;
    logger({ type: 'scope_violation', reason, url, details });
  }

  function matchesAllowlist(value) {
    if (allowPatterns.length === 0) {
      return unsafeFollow;
    }
    return allowPatterns.some((entry) => entry.expression.test(value));
  }

  function withinBaseScope(candidate) {
    switch (normalisedMode) {
      case 'domain':
        return deriveRegistrableDomain(candidate.hostname.toLowerCase()) === seedDomain;
      case 'custom':
        if (allowPatterns.length > 0) {
          return true;
        }
        return candidate.origin === seedOrigin;
      case 'origin':
      default:
        return candidate.origin === seedOrigin;
    }
  }

  function check(value, meta = {}) {
    if (typeof value !== 'string' || value.trim() === '') {
      logViolation(value || '', 'invalid_url', meta);
      return false;
    }

    let candidate;
    try {
      candidate = new URL(value);
    } catch (error) {
      logViolation(value, 'invalid_url', Object.assign({ error: error.message }, meta));
      return false;
    }

    const serialised = candidate.toString();
    const protocol = candidate.protocol.replace(/:$/, '').toLowerCase();

    if (!protocolSet.has(protocol)) {
      logViolation(serialised, 'protocol_blocked', Object.assign({ protocol }, meta));
      return false;
    }

    if (!allowPrivate && isPrivateHostname(candidate.hostname)) {
      logViolation(serialised, 'private_address_blocked', Object.assign({ host: candidate.hostname }, meta));
      return false;
    }

    if (!withinBaseScope(candidate)) {
      logViolation(serialised, 'out_of_scope', Object.assign({ mode: normalisedMode }, meta));
      return false;
    }

    if (!unsafeFollow && !matchesAllowlist(serialised)) {
      logViolation(
        serialised,
        'not_in_allowlist',
        Object.assign({ allowlist: allowPatterns.map((entry) => entry.pattern) }, meta)
      );
      return false;
    }

    return true;
  }

  return { check };
}

function deriveRegistrableDomain(hostname) {
  if (typeof hostname !== 'string') {
    return '';
  }
  const trimmed = hostname.trim().toLowerCase();
  if (trimmed === '') {
    return '';
  }
  const labels = trimmed.split('.').filter((label) => label !== '');
  if (labels.length <= 2) {
    return labels.join('.');
  }
  return labels.slice(-2).join('.');
}

function isPrivateHostname(hostname) {
  if (typeof hostname !== 'string') {
    return false;
  }
  const value = hostname.trim().toLowerCase();
  if (value === '') {
    return false;
  }
  if (value === 'localhost') {
    return true;
  }

  const unwrapped = value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;

  const mappedMatch = unwrapped.startsWith('::ffff:') ? unwrapped.slice(7) : null;
  if (mappedMatch && net.isIPv4(mappedMatch)) {
    return isPrivateIPv4(mappedMatch);
  }

  if (net.isIPv4(unwrapped)) {
    return isPrivateIPv4(unwrapped);
  }

  if (net.isIPv6(unwrapped)) {
    return isPrivateIPv6(unwrapped);
  }

  return false;
}

function isPrivateIPv4(address) {
  const octets = address.split('.').map((segment) => Number.parseInt(segment, 10));
  if (octets.length !== 4 || octets.some((octet) => !Number.isFinite(octet) || octet < 0 || octet > 255)) {
    return false;
  }
  if (octets[0] === 10) {
    return true;
  }
  if (octets[0] === 127) {
    return true;
  }
  if (octets[0] === 169 && octets[1] === 254) {
    return true;
  }
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) {
    return true;
  }
  if (octets[0] === 192 && octets[1] === 168) {
    return true;
  }
  if (octets[0] === 0) {
    return true;
  }
  return false;
}

const IPV6_RANGES = [
  { start: parseIPv6('::1'), end: parseIPv6('::1') },
  { start: parseIPv6('fc00::'), end: parseIPv6('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') },
  { start: parseIPv6('fe80::'), end: parseIPv6('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff') },
];

function isPrivateIPv6(address) {
  const target = parseIPv6(address);
  if (target === null) {
    return false;
  }
  return IPV6_RANGES.some((range) => target >= range.start && target <= range.end);
}

function parseIPv6(address) {
  if (!net.isIPv6(address)) {
    return null;
  }
  const lower = address.toLowerCase();
  const hasIpv4Tail = lower.includes('.');
  let ipv4Tail = null;
  let base = lower;
  if (hasIpv4Tail) {
    const lastColon = lower.lastIndexOf(':');
    ipv4Tail = lower.slice(lastColon + 1);
    base = lower.slice(0, lastColon);
    if (!net.isIPv4(ipv4Tail)) {
      return null;
    }
  }

  const parts = base.split('::');
  if (parts.length > 2) {
    return null;
  }

  const head = parts[0] ? parts[0].split(':').filter(Boolean) : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':').filter(Boolean) : [];
  const fill = 8 - (head.length + tail.length + (ipv4Tail ? 2 : 0));
  if (fill < 0) {
    return null;
  }
  const expanded = head
    .concat(Array(fill).fill('0'))
    .concat(tail)
    .map((segment) => segment || '0');

  if (ipv4Tail) {
    const ipv4Octets = ipv4Tail.split('.').map((segment) => Number.parseInt(segment, 10));
    if (ipv4Octets.length !== 4) {
      return null;
    }
    expanded.push(
      ((ipv4Octets[0] << 8) | ipv4Octets[1]).toString(16),
      ((ipv4Octets[2] << 8) | ipv4Octets[3]).toString(16)
    );
  }

  if (expanded.length !== 8) {
    return null;
  }

  return expanded.reduce((acc, segment) => {
    const value = segment ? Number.parseInt(segment, 16) : 0;
    if (!Number.isFinite(value) || value < 0 || value > 0xffff) {
      throw new Error('invalid hextet');
    }
    return (acc << 16n) + BigInt(value);
  }, 0n);
}

module.exports = {
  createScopeChecker,
  deriveRegistrableDomain,
  isPrivateHostname,
};
