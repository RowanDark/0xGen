#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

function usage() {
  console.error('Usage: normalize.js <amass-json> [out.jsonl]');
}

function safeTimestamp(value) {
  if (!value) {
    return new Date().toISOString();
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return new Date().toISOString();
  }
  return parsed.toISOString();
}

function main() {
  const [, , inputArg, outputArg] = process.argv;

  if (!inputArg) {
    usage();
    process.exit(1);
  }

  const defaultOut = path.join(process.env['0XGEN_OUT'] || '/out', 'assets.jsonl');
  const outputPath = outputArg ? path.resolve(outputArg) : defaultOut;

  const inputPath = inputArg === '-' ? 0 : path.resolve(inputArg);
  let raw = '';

  try {
    raw = inputArg === '-' ? fs.readFileSync(process.stdin.fd, 'utf8') : fs.readFileSync(inputPath, 'utf8');
  } catch (err) {
    console.error(`Failed to read input: ${err.message}`);
    process.exit(1);
  }

  const seen = new Map();
  raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .forEach((line, idx) => {
      let payload;
      try {
        payload = JSON.parse(line);
      } catch (err) {
        console.warn(`Skipping line ${idx + 1}: ${err.message}`);
        return;
      }

      const name = typeof payload.name === 'string' ? payload.name.trim() : '';
      if (!name) {
        return;
      }

      const ts = safeTimestamp(payload.timestamp || payload.timestr || payload.last_seen);
      const existing = seen.get(name);
      if (!existing || existing.ts > ts) {
        seen.set(name, {
          type: 'subdomain',
          value: name,
          source: 'amass',
          ts,
        });
      }
    });

  const records = Array.from(seen.values()).sort((a, b) => a.value.localeCompare(b.value));

  try {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    const body = records.map((record) => JSON.stringify(record)).join('\n');
    const output = body.length > 0 ? `${body}\n` : '';
    fs.writeFileSync(outputPath, output);
  } catch (err) {
    console.error(`Failed to write output: ${err.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}
