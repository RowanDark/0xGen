'use strict';

const fs = require('node:fs');

function loadScopePolicy(filePath) {
  if (typeof filePath !== 'string' || filePath.trim() === '') {
    return null;
  }
  const trimmed = filePath.trim();
  let data;
  try {
    data = fs.readFileSync(trimmed, 'utf8');
  } catch (error) {
    throw new Error(`read scope policy ${trimmed}: ${error.message}`);
  }
  const parsed = parsePolicyYAML(data);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('scope policy must be a YAML mapping');
  }
  const policy = {
    version: typeof parsed.version === 'number' ? parsed.version : 1,
    allow: Array.isArray(parsed.allow) ? parsed.allow : [],
    deny: Array.isArray(parsed.deny) ? parsed.deny : [],
  };
  if (typeof parsed.private_networks === 'string') {
    policy.privateNetworks = parsed.private_networks.trim().toLowerCase();
  }
  if (typeof parsed.pii === 'string') {
    policy.pii = parsed.pii.trim().toLowerCase();
  }
  return policy;
}

function parsePolicyYAML(content) {
  const lines = String(content || '')
    .split(/\r?\n/)
    .map((line) => line.replace(/\s+$/, ''));
  const result = { allow: [], deny: [] };
  let currentKey = null;
  let currentList = null;
  let currentItem = null;

  for (const rawLine of lines) {
    if (!rawLine) {
      continue;
    }
    if (!rawLine.startsWith(' ')) {
      currentItem = null;
      currentList = null;
      const { key, value } = parseKeyValue(rawLine);
      switch (key) {
        case 'version':
          result.version = typeof value === 'number' ? value : Number.parseInt(String(value), 10);
          if (!Number.isFinite(result.version)) {
            result.version = 1;
          }
          break;
        case 'allow':
          currentKey = 'allow';
          currentList = result.allow;
          break;
        case 'deny':
          currentKey = 'deny';
          currentList = result.deny;
          break;
        case 'private_networks':
          result.private_networks = typeof value === 'string' ? value : String(value || '').trim();
          break;
        case 'pii':
          result.pii = typeof value === 'string' ? value : String(value || '').trim();
          break;
        default:
          currentKey = null;
          currentList = null;
          break;
      }
      continue;
    }

    if (!currentKey) {
      continue;
    }

    if (rawLine.trim() === '[]') {
      result[currentKey] = [];
      currentList = result[currentKey];
      currentItem = null;
      continue;
    }

    if (rawLine.startsWith('  -')) {
      currentItem = {};
      currentList.push(currentItem);
      const inline = rawLine.slice(3).trim();
      if (inline) {
        const { key, value } = parseKeyValue(inline);
        if (key) {
          currentItem[key] = value;
        }
      }
      continue;
    }

    if (!currentItem) {
      continue;
    }

    if (rawLine.startsWith('    ')) {
      const { key, value } = parseKeyValue(rawLine.trim());
      if (key) {
        currentItem[key] = value;
      }
    }
  }

  return result;
}

function parseKeyValue(segment) {
  if (typeof segment !== 'string') {
    return { key: '', value: '' };
  }
  const idx = segment.indexOf(':');
  if (idx === -1) {
    return { key: segment.trim(), value: '' };
  }
  const key = segment.slice(0, idx).trim();
  const raw = segment.slice(idx + 1).trim();
  return { key, value: parseScalar(raw) };
}

function parseScalar(raw) {
  if (raw === '') {
    return '';
  }
  if (raw === '[]') {
    return [];
  }
  if (raw.startsWith('"') && raw.endsWith('"')) {
    return unquote(raw.slice(1, -1));
  }
  const numeric = Number.parseFloat(raw);
  if (!Number.isNaN(numeric) && String(numeric) === raw) {
    return numeric;
  }
  return raw;
}

function unquote(value) {
  let result = '';
  let escaping = false;
  for (const char of value) {
    if (escaping) {
      switch (char) {
        case 'n':
          result += '\n';
          break;
        case 'r':
          result += '\r';
          break;
        case 't':
          result += '\t';
          break;
        case '"':
        case '\\':
          result += char;
          break;
        default:
          result += char;
          break;
      }
      escaping = false;
      continue;
    }
    if (char === '\\') {
      escaping = true;
      continue;
    }
    result += char;
  }
  return result;
}

module.exports = { loadScopePolicy };
