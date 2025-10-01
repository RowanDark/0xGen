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
    denylist = [],
    unsafeFollow = false,
    allowPrivate = false,
    allowedProtocols,
    logger = defaultLogger,
  } = context;

  const seedDomain = deriveRegistrableDomain(seedHost);
  const allowRules = buildRuleSet('allow', allowlist, seedUrl, logger);
  const denyRules = buildRuleSet('deny', denylist, seedUrl, logger);

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

  function matchesAllowlist(candidate, serialised) {
    if (allowRules.matchers.length === 0) {
      return unsafeFollow;
    }
    return allowRules.matchers.some((fn) => safeInvoke(fn, candidate, serialised));
  }

  function matchesDenylist(candidate, serialised) {
    if (denyRules.matchers.length === 0) {
      return false;
    }
    return denyRules.matchers.some((fn) => safeInvoke(fn, candidate, serialised));
  }

  function withinBaseScope(candidate) {
    switch (normalisedMode) {
      case 'domain':
        return deriveRegistrableDomain(candidate.hostname.toLowerCase()) === seedDomain;
      case 'custom':
        if (allowRules.matchers.length > 0) {
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

    if (matchesDenylist(candidate, serialised)) {
      logViolation(
        serialised,
        'denied_by_policy',
        Object.assign({ denylist: denyRules.descriptors }, meta)
      );
      return false;
    }

    if (!withinBaseScope(candidate)) {
      logViolation(serialised, 'out_of_scope', Object.assign({ mode: normalisedMode }, meta));
      return false;
    }

    if (!unsafeFollow && !matchesAllowlist(candidate, serialised)) {
      logViolation(
        serialised,
        'not_in_allowlist',
        Object.assign({ allowlist: allowRules.descriptors }, meta)
      );
      return false;
    }

    return true;
  }

  return { check };
}

function buildRuleSet(kind, entries, seedUrl, logger) {
  const list = Array.isArray(entries) ? entries : entries ? [entries] : [];
  const matchers = [];
  const descriptors = [];
  for (const entry of list) {
    const compiled = compileRule(kind, entry, seedUrl, logger);
    if (compiled) {
      matchers.push(compiled.matches);
      descriptors.push(compiled.describe);
    }
  }
  return { matchers, descriptors };
}

function compileRule(kind, entry, seedUrl, logger) {
  if (typeof entry === 'string') {
    return compilePatternRule(kind, entry, seedUrl, logger);
  }
  if (!entry || typeof entry !== 'object') {
    return null;
  }

  const rawType = typeof entry.type === 'string' ? entry.type.trim().toLowerCase() : '';
  const rawPattern = typeof entry.pattern === 'string' ? entry.pattern.trim() : '';
  const rawValue = typeof entry.value === 'string' ? entry.value.trim() : '';
  const type = rawType || (rawPattern !== '' ? 'pattern' : '');
  const value = rawValue || rawPattern;

  if (type === '' || value === '') {
    return null;
  }

  switch (type) {
    case 'pattern':
    case 'regex':
      return compilePatternRule(kind, value, seedUrl, logger);
    case 'domain': {
      const domain = value.toLowerCase();
      return {
        matches: (candidate) => hostMatchesDomain(candidate.hostname, domain),
        describe: `domain:${domain}`,
      };
    }
    case 'wildcard': {
      const regex = wildcardToRegExp(value);
      if (!regex) {
        logRuleError(kind, seedUrl, logger, { pattern: value, error: 'invalid wildcard pattern' });
        return null;
      }
      return {
        matches: (candidate) => regex.test((candidate.hostname || '').toLowerCase()),
        describe: `wildcard:${value}`,
      };
    }
    case 'url':
      return {
        matches: (_, serialised) => serialised === value,
        describe: `url:${value}`,
      };
    case 'url_prefix':
      return {
        matches: (_, serialised) => serialised.startsWith(value),
        describe: `url_prefix:${value}`,
      };
    case 'path': {
      const normalised = value.startsWith('/') ? value : `/${value}`;
      return {
        matches: (candidate) => candidate.pathname.startsWith(normalised),
        describe: `path:${normalised}`,
      };
    }
    case 'cidr': {
      const cidr = parseCIDR(value);
      if (!cidr) {
        logRuleError(kind, seedUrl, logger, { value, error: 'invalid cidr' });
        return null;
      }
      return {
        matches: (candidate) => cidrContains(cidr, candidate.hostname),
        describe: `cidr:${value}`,
      };
    }
    case 'ip':
      return {
        matches: (candidate) => (candidate.hostname || '').toLowerCase() === value.toLowerCase(),
        describe: `ip:${value.toLowerCase()}`,
      };
    default:
      logRuleError(kind, seedUrl, logger, {
        type,
        value,
        error: 'unsupported rule type',
      });
      return null;
  }
}

function compilePatternRule(kind, pattern, seedUrl, logger) {
  if (typeof pattern !== 'string' || pattern.trim() === '') {
    return null;
  }
  try {
    const expression = new RegExp(pattern);
    return {
      matches: (_, serialised) => expression.test(serialised),
      describe: `pattern:${pattern}`,
    };
  } catch (error) {
    logRuleError(kind, seedUrl, logger, { pattern, error: error.message });
    return null;
  }
}

function logRuleError(kind, seedUrl, logger, details) {
  if (typeof logger !== 'function') {
    return;
  }
  const reason = kind === 'allow' ? 'invalid_allowlist_pattern' : 'invalid_denylist_rule';
  try {
    logger({
      type: 'scope_violation',
      reason,
      url: seedUrl ? seedUrl.toString() : '',
      details,
    });
  } catch (error) {
    // ignore logger failures
  }
}

function wildcardToRegExp(pattern) {
  if (typeof pattern !== 'string') {
    return null;
  }
  const trimmed = pattern.trim();
  if (trimmed === '') {
    return null;
  }
  const escaped = trimmed.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  const regex = `^${escaped.replace(/\\\*/g, '.*')}$`;
  try {
    return new RegExp(regex.toLowerCase());
  } catch (error) {
    return null;
  }
}

function hostMatchesDomain(hostname, domain) {
  if (typeof hostname !== 'string' || typeof domain !== 'string') {
    return false;
  }
  const host = hostname.trim().toLowerCase();
  const target = domain.trim().toLowerCase();
  if (host === '' || target === '') {
    return false;
  }
  return host === target || host.endsWith(`.${target}`);
}

function safeInvoke(fn, candidate, serialised) {
  try {
    return fn(candidate, serialised);
  } catch (error) {
    return false;
  }
}

function parseCIDR(value) {
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed === '') {
    return null;
  }
  const parts = trimmed.split('/');
  if (parts.length !== 2) {
    return null;
  }
  const rawAddress = parts[0].trim();
  const address = unwrapHost(rawAddress);
  const prefix = Number.parseInt(parts[1], 10);
  if (!Number.isFinite(prefix)) {
    return null;
  }

  const version = net.isIP(address);
  if (version === 4) {
    if (prefix < 0 || prefix > 32) {
      return null;
    }
    const octets = address.split('.').map((segment) => Number.parseInt(segment, 10));
    if (octets.length !== 4 || octets.some((segment) => !Number.isFinite(segment) || segment < 0 || segment > 255)) {
      return null;
    }
    const baseInt = ipToInteger(octets);
    if (baseInt === null) {
      return null;
    }
    const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0) >>> 0;
    return { version: 4, base: baseInt, mask };
  }

  if (version === 6) {
    if (prefix < 0 || prefix > 128) {
      return null;
    }
    const parsed = parseIPv6(address);
    if (parsed === null) {
      return null;
    }
    const mask = prefix === 0 ? 0n : BigInt.asUintN(128, (-1n << BigInt(128 - prefix)));
    return { version: 6, base: parsed, mask };
  }

  return null;
}

function cidrContains(cidr, host) {
  if (!cidr || typeof host !== 'string') {
    return false;
  }
  const cleaned = host.trim();
  if (cleaned === '') {
    return false;
  }
  const address = unwrapHost(cleaned);
  const version = net.isIP(address);
  if (version === 4 && cidr.version === 4) {
    const ip = ipToInteger(address.split('.').map((segment) => Number.parseInt(segment, 10)));
    if (ip === null) {
      return false;
    }
    return (ip & cidr.mask) === (cidr.base & cidr.mask);
  }
  if (version === 6 && cidr.version === 6) {
    const target = parseIPv6(address);
    if (target === null) {
      return false;
    }
    return (target & cidr.mask) === (cidr.base & cidr.mask);
  }
  return false;
}

function unwrapHost(value) {
  if (typeof value !== 'string') {
    return '';
  }
  if (value.startsWith('[') && value.endsWith(']')) {
    return value.slice(1, -1);
  }
  return value;
}

function ipToInteger(parts) {
  if (!Array.isArray(parts) || parts.length !== 4) {
    return null;
  }
  let value = 0;
  for (const part of parts) {
    if (!Number.isFinite(part) || part < 0 || part > 255) {
      return null;
    }
    value = (value << 8) | part;
  }
  return value >>> 0;
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
