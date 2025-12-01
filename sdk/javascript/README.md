# 0xGen JavaScript SDK

Official JavaScript/TypeScript SDK for the 0xGen Security Scanner API.

## Features

- ✅ **Full TypeScript support** with comprehensive type definitions
- ✅ **Error handling** with custom error types and detailed error information
- ✅ **Automatic retries** with exponential backoff for transient failures
- ✅ **Polling utilities** to wait for scan completion
- ✅ **Request timeouts** and abort controller support
- ✅ **Modern async/await** API
- ✅ **Zero dependencies** (uses native fetch)

## Installation

```bash
npm install @0xgen/sdk
```

Or with yarn:

```bash
yarn add @0xgen/sdk
```

## Quick Start

```typescript
import { OxGenClient, waitForScan } from '@0xgen/sdk';

// Create client with API key
const client = new OxGenClient({
  baseURL: 'https://api.0xgen.com',
  apiKey: 'your-api-key-here',
});

// Create and monitor a scan
async function runScan() {
  try {
    // Start a scan
    const response = await client.createScan({
      plugin: 'excavator',
    });

    console.log(`Scan created: ${response.scan_id}`);

    // Wait for scan to complete (with progress updates)
    const scan = await waitForScan(client, response.scan_id, {
      timeout: 300000, // 5 minutes
      interval: 2000,  // Check every 2 seconds
      onProgress: (scan) => {
        console.log(`Scan status: ${scan.status}`);
      },
    });

    // Get results
    const results = await client.getScanResults(scan.id);
    console.log(`Found ${results.findings.length} findings`);

  } catch (error) {
    console.error('Scan failed:', error.message);
  }
}

runScan();
```

## API Reference

### Client Configuration

```typescript
const client = new OxGenClient({
  baseURL: 'https://api.0xgen.com',  // Required: API base URL
  apiKey: 'your-api-key',             // Optional: Bearer token for authentication
  staticToken: 'static-token',        // Optional: For token issuance
  timeout: 30000,                     // Optional: Request timeout (default: 30s)
  headers: {                          // Optional: Custom headers
    'X-Custom-Header': 'value',
  },
});
```

### Authentication

#### Issue API Token

```typescript
const tokenResponse = await client.issueToken('static-management-token', {
  subject: 'user@example.com',
  audience: 'api',
  ttl_seconds: 3600,
  workspace_id: 'workspace-123',
  role: 'analyst',
});

console.log(`Token: ${tokenResponse.token}`);
console.log(`Expires: ${tokenResponse.expires_at}`);

// Use the token for subsequent requests
const authenticatedClient = new OxGenClient({
  baseURL: 'https://api.0xgen.com',
  apiKey: tokenResponse.token,
});
```

### Plugin Management

#### List Plugins

```typescript
const { plugins } = await client.listPlugins();

plugins.forEach(plugin => {
  console.log(`${plugin.name} v${plugin.version}: ${plugin.description}`);
});
```

### Scan Management

#### Create Scan

```typescript
const response = await client.createScan({
  plugin: 'excavator',
});

console.log(`Scan ID: ${response.scan_id}`);
console.log(`Status: ${response.status}`);
```

#### Get Scan Status

```typescript
const scan = await client.getScanStatus('scan-id-123');

console.log(`Status: ${scan.status}`);
console.log(`Created: ${scan.created_at}`);
console.log(`Logs: ${scan.logs.join('\n')}`);
```

#### Get Scan Results

```typescript
const results = await client.getScanResults('scan-id-123');

console.log(`Plugin: ${results.plugin}`);
console.log(`Findings: ${results.findings.length}`);
console.log(`Signature: ${results.signature}`);

results.findings.forEach(finding => {
  console.log(`[${finding.severity}] ${finding.title}`);
  console.log(`  URL: ${finding.url}`);
  console.log(`  Description: ${finding.description}`);
});
```

### Utility Functions

#### Wait for Scan Completion

```typescript
import { waitForScan } from '@0xgen/sdk';

const scan = await waitForScan(client, scanId, {
  timeout: 300000,    // Maximum wait time (5 minutes)
  interval: 2000,     // Poll every 2 seconds
  onProgress: (scan) => {
    console.log(`Current status: ${scan.status}`);
  },
});
```

#### Wait for Multiple Scans

```typescript
import { waitForScans } from '@0xgen/sdk';

const scans = await waitForScans(client, ['scan-1', 'scan-2', 'scan-3'], {
  timeout: 600000, // 10 minutes for all scans
});

console.log(`All ${scans.length} scans completed`);
```

#### Scan and Wait (One-liner)

```typescript
import { scanAndWait } from '@0xgen/sdk';

const { scan, results } = await scanAndWait(client, 'excavator', {
  onProgress: (s) => console.log(`Progress: ${s.status}`),
});

console.log(`Scan completed with ${results.findings.length} findings`);
```

#### Automatic Retry

```typescript
import { withRetry } from '@0xgen/sdk';

const results = await withRetry(
  () => client.getScanResults(scanId),
  {
    maxRetries: 3,
    initialDelay: 1000,
    maxDelay: 10000,
    backoffMultiplier: 2,
  }
);
```

#### Finding Utilities

```typescript
import {
  groupFindingsBySeverity,
  filterBySeverity
} from '@0xgen/sdk';

// Group findings by severity
const grouped = groupFindingsBySeverity(results.findings);
console.log(`Critical: ${grouped.critical.length}`);
console.log(`High: ${grouped.high.length}`);
console.log(`Medium: ${grouped.medium.length}`);

// Filter to only high and critical
const critical = filterBySeverity(results.findings, 'high');
console.log(`High+ severity findings: ${critical.length}`);
```

### Cipher Operations

The SDK includes support for cipher/encoding operations:

```typescript
// Execute a cipher operation
const result = await client.executeCipher({
  input: 'SGVsbG8gV29ybGQ=',
  operation: 'base64_decode',
});
console.log(result.output); // "Hello World"

// Smart decode (auto-detect encoding)
const decoded = await client.smartDecode('SGVsbG8gV29ybGQ=');
console.log(decoded.output);

// Detect encoding
const detection = await client.detectCipher('SGVsbG8gV29ybGQ=');
console.log(detection.detected);

// List available operations
const operations = await client.listCipherOperations();

// Save a recipe
await client.saveCipherRecipe({
  name: 'my-recipe',
  operations: [
    { operation: 'base64_decode' },
    { operation: 'url_decode' },
  ],
});

// List recipes
const recipes = await client.listCipherRecipes();

// Load and delete recipes
const recipe = await client.loadCipherRecipe('my-recipe');
await client.deleteCipherRecipe('my-recipe');
```

## Error Handling

The SDK uses a custom `OxGenAPIError` class that includes:
- `message`: Error description
- `status`: HTTP status code
- `details`: Additional error information

```typescript
import { OxGenAPIError } from '@0xgen/sdk';

try {
  const scan = await client.getScanStatus('invalid-id');
} catch (error) {
  if (error instanceof OxGenAPIError) {
    console.error(`API Error ${error.status}: ${error.message}`);
    console.error('Details:', error.details);

    // Handle specific error codes
    if (error.status === 404) {
      console.error('Scan not found');
    } else if (error.status === 401) {
      console.error('Authentication failed');
    } else if (error.status === 408) {
      console.error('Request timeout');
    }
  } else {
    console.error('Unexpected error:', error);
  }
}
```

## TypeScript Support

The SDK is written in TypeScript and includes comprehensive type definitions:

```typescript
import type {
  Scan,
  ScanResult,
  Finding,
  Severity,
  ScanStatus,
  Plugin,
} from '@0xgen/sdk';

const scan: Scan = await client.getScanStatus('scan-id');
const severity: Severity = 'critical';
const status: ScanStatus = 'completed';
```

## Examples

### Example 1: Basic Scan

```typescript
import { OxGenClient, scanAndWait } from '@0xgen/sdk';

const client = new OxGenClient({
  baseURL: process.env.OXGEN_API_URL!,
  apiKey: process.env.OXGEN_API_KEY!,
});

async function basicScan() {
  const { scan, results } = await scanAndWait(client, 'excavator');

  console.log(`Scan ${scan.id} completed in ${formatDuration(scan)}`);
  console.log(`Found ${results.findings.length} findings`);
}

basicScan().catch(console.error);
```

### Example 2: Advanced Error Handling

```typescript
import { OxGenClient, waitForScan, OxGenAPIError } from '@0xgen/sdk';

async function advancedScan() {
  const client = new OxGenClient({
    baseURL: process.env.OXGEN_API_URL!,
    apiKey: process.env.OXGEN_API_KEY!,
    timeout: 60000,
  });

  try {
    // Create scan
    const { scan_id } = await client.createScan({ plugin: 'excavator' });

    // Wait with progress tracking
    const scan = await waitForScan(client, scan_id, {
      timeout: 600000, // 10 minutes
      onProgress: (s) => {
        console.log(`[${new Date().toISOString()}] Status: ${s.status}`);
        if (s.logs.length > 0) {
          console.log(`  Latest log: ${s.logs[s.logs.length - 1]}`);
        }
      },
    });

    // Get results
    const results = await client.getScanResults(scan_id);

    // Process findings
    const criticalFindings = results.findings.filter(
      f => f.severity === 'critical'
    );

    if (criticalFindings.length > 0) {
      console.error(`⚠️  Found ${criticalFindings.length} critical findings!`);
      criticalFindings.forEach(f => {
        console.error(`  - ${f.title} at ${f.url}`);
      });
      process.exit(1);
    }

  } catch (error) {
    if (error instanceof OxGenAPIError) {
      if (error.status === 401) {
        console.error('Authentication failed. Check your API key.');
      } else if (error.status === 408) {
        console.error('Request timeout. The scan is taking too long.');
      } else {
        console.error(`API Error: ${error.message}`);
      }
    } else {
      console.error('Unexpected error:', error);
    }
    process.exit(1);
  }
}

advancedScan();
```

### Example 3: Parallel Scans

```typescript
import { OxGenClient, waitForScans } from '@0xgen/sdk';

async function parallelScans() {
  const client = new OxGenClient({
    baseURL: process.env.OXGEN_API_URL!,
    apiKey: process.env.OXGEN_API_KEY!,
  });

  // Get available plugins
  const { plugins } = await client.listPlugins();

  // Start scans for all plugins
  const scanIds = await Promise.all(
    plugins.map(async (plugin) => {
      const response = await client.createScan({ plugin: plugin.id });
      console.log(`Started scan ${response.scan_id} with ${plugin.name}`);
      return response.scan_id;
    })
  );

  // Wait for all scans to complete
  console.log(`Waiting for ${scanIds.length} scans...`);
  const scans = await waitForScans(client, scanIds, {
    timeout: 1800000, // 30 minutes for all
  });

  console.log(`All scans completed!`);

  // Collect all results
  const allResults = await Promise.all(
    scanIds.map(id => client.getScanResults(id))
  );

  // Aggregate findings
  const totalFindings = allResults.reduce(
    (sum, r) => sum + r.findings.length,
    0
  );

  console.log(`Total findings across all scans: ${totalFindings}`);
}

parallelScans().catch(console.error);
```

## Requirements

- Node.js >= 16.0.0
- Modern browser with fetch support (or node-fetch polyfill for older Node versions)

## License

MIT

## Support

For issues and questions:
- GitHub Issues: https://github.com/RowanDark/0xgen/issues
- Documentation: https://docs.0xgen.com

## Contributing

Contributions are welcome! Please see our contributing guidelines for details.
