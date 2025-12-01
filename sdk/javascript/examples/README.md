# 0xGen SDK Examples

This directory contains practical examples demonstrating how to use the 0xGen JavaScript SDK.

## Prerequisites

Before running these examples:

1. Build the SDK:
   ```bash
   cd ..
   npm install
   npm run build
   ```

2. Set environment variables:
   ```bash
   export OXGEN_API_URL="http://localhost:8080"
   export OXGEN_API_KEY="your-api-key-here"
   ```

   Or create a `.env` file:
   ```env
   OXGEN_API_URL=http://localhost:8080
   OXGEN_API_KEY=your-api-key
   ```

## Examples

### 1. Basic Scan (`basic-scan.js`)

Demonstrates the fundamental workflow:
- Creating a client
- Starting a scan
- Monitoring progress
- Retrieving results

**Run:**
```bash
node basic-scan.js
```

**What it does:**
- Creates a scan with the "excavator" plugin
- Polls the scan status every 2 seconds
- Displays progress updates and logs
- Shows findings summary by severity

### 2. Parallel Scans (`parallel-scans.js`)

Shows how to run multiple scans concurrently:
- Starting multiple scans
- Monitoring them in parallel
- Aggregating results

**Run:**
```bash
node parallel-scans.js
```

**What it does:**
- Lists available plugins
- Starts scans for the first 3 plugins
- Waits for all scans to complete
- Aggregates and displays combined results
- Shows per-plugin breakdown

### 3. Cipher Operations (`cipher-operations.js`)

Demonstrates cipher/encoding features:
- Executing cipher operations
- Auto-detecting encodings
- Working with recipes

**Run:**
```bash
node cipher-operations.js
```

**What it does:**
- Decodes Base64 encoded strings
- Uses smart decode to auto-detect encoding
- Lists available cipher operations
- Creates, saves, and deletes recipes

### 4. Error Handling (`error-handling.js`)

Comprehensive error handling examples:
- Catching API errors
- Handling timeouts
- Implementing retry logic
- Dealing with network errors

**Run:**
```bash
node error-handling.js
```

**What it does:**
- Demonstrates catching `OxGenAPIError`
- Shows handling of different HTTP status codes
- Illustrates timeout behavior
- Demonstrates automatic retry with exponential backoff
- Shows that client errors (4xx) are not retried

## Common Patterns

### Environment Variables

All examples support these environment variables:

- `OXGEN_API_URL` - API base URL (default: `http://localhost:8080`)
- `OXGEN_API_KEY` - Authentication token (required)

### Error Handling Pattern

```javascript
const { OxGenAPIError } = require('@0xgen/sdk');

try {
  // API operation
} catch (error) {
  if (error instanceof OxGenAPIError) {
    console.error(`API Error ${error.status}: ${error.message}`);
  } else {
    console.error('Unexpected error:', error);
  }
}
```

### Progress Monitoring Pattern

```javascript
const scan = await waitForScan(client, scanId, {
  onProgress: (scan) => {
    console.log(`Status: ${scan.status}`);
    if (scan.logs.length > 0) {
      console.log(`Latest: ${scan.logs[scan.logs.length - 1]}`);
    }
  },
});
```

## Troubleshooting

### "Cannot find module '../dist'"

Make sure you've built the SDK:
```bash
cd ..
npm run build
```

### "Unauthorized" or 401 errors

Check that your `OXGEN_API_KEY` is set correctly and has the required permissions.

### "Connection refused" errors

Ensure the 0xGen API server is running at the specified `OXGEN_API_URL`.

### Timeout errors

For long-running scans, increase the timeout:
```javascript
const scan = await waitForScan(client, scanId, {
  timeout: 600000, // 10 minutes
});
```

## Creating Your Own Examples

Template for a new example:

```javascript
const { OxGenClient } = require('@0xgen/sdk');

async function main() {
  const client = new OxGenClient({
    baseURL: process.env.OXGEN_API_URL || 'http://localhost:8080',
    apiKey: process.env.OXGEN_API_KEY,
  });

  try {
    // Your code here

  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();
```

## Next Steps

After trying these examples:

1. Read the [main README](../README.md) for full API documentation
2. Explore the [TypeScript type definitions](../src/types.ts)
3. Check out the [source code](../src/) for implementation details

## Support

For issues or questions:
- GitHub Issues: https://github.com/RowanDark/0xgen/issues
- Documentation: https://docs.0xgen.com
