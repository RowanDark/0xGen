# 0xGen Plugin SDK for Node.js

Node.js/JavaScript SDK for creating 0xGen security scanner plugins.

## Overview

This SDK allows you to create security scanner plugins in JavaScript/Node.js that integrate with the 0xGen platform via gRPC. Plugins can:

- Receive HTTP traffic events (passive analysis)
- Emit security findings
- Access workspace and secrets
- Perform active security checks

## Installation

```bash
npm install @grpc/grpc-js @grpc/proto-loader
```

Then require the SDK in your plugin:

```javascript
const { register, Severity, Capability } = require('../../sdk/plugin-sdk');
```

## Quick Start

### Basic Plugin

```javascript
const { register, Severity } = require('../../sdk/plugin-sdk');

register({
  name: 'my-plugin',

  onStart: async ({ ctx, config }) => {
    ctx.log('info', 'Plugin started');

    // Emit a test finding
    await ctx.emitFinding({
      type: 'test-finding',
      message: 'Plugin initialized successfully',
      severity: Severity.INFO,
    });
  },

  onHTTPPassive: async ({ ctx, event }) => {
    // Analyze HTTP responses
    const response = event.response;

    if (response && response.headers['x-debug-enabled']) {
      await ctx.emitFinding({
        type: 'debug-header-exposed',
        message: 'Debug header exposed in response',
        severity: Severity.MEDIUM,
        target: response.headers['host'],
        evidence: 'X-Debug-Enabled: ' + response.headers['x-debug-enabled'],
      });
    }
  },
});
```

### Passive Security Scanner

```javascript
const { register, Severity, Capability } = require('../../sdk/plugin-sdk');

register({
  name: 'security-header-scanner',
  capabilities: [Capability.EMIT_FINDINGS, Capability.HTTP_PASSIVE],

  onHTTPPassive: async ({ ctx, event }) => {
    const response = event.response;
    if (!response) return;

    // Check for missing security headers
    const securityHeaders = [
      'strict-transport-security',
      'x-frame-options',
      'x-content-type-options',
      'content-security-policy',
    ];

    for (const header of securityHeaders) {
      if (!response.headers[header]) {
        await ctx.emitFinding({
          type: 'missing-security-header',
          message: `Missing security header: ${header}`,
          severity: Severity.MEDIUM,
          metadata: {
            header: header,
            status: response.statusLine,
          },
        });
      }
    }

    // Check for sensitive data exposure
    const bodyText = response.body.toString('utf-8');
    if (bodyText.includes('password') || bodyText.includes('secret')) {
      await ctx.emitFinding({
        type: 'potential-data-exposure',
        message: 'Response body may contain sensitive data',
        severity: Severity.HIGH,
        evidence: 'Body contains keywords: password, secret',
      });
    }
  },
});
```

## API Reference

### `register(config)`

Main entry point for registering a plugin.

**Parameters:**
- `config.name` (string, required) - Plugin name
- `config.onStart` (function) - Called when plugin starts
- `config.onHTTPPassive` (function) - Called for passive HTTP events
- `config.onHTTPActive` (function) - Called for active HTTP events
- `config.capabilities` (array) - Required capabilities
- `config.subscriptions` (array) - Event subscriptions
- `config.logger` (function) - Custom logger

**Returns:** Promise<Context>

### Context Methods

#### `ctx.emitFinding(finding)`

Emit a security finding to the host.

**Parameters:**
```javascript
{
  type: string,        // Required: Finding type
  message: string,     // Required: Human-readable message
  severity: number,    // Optional: Severity level (default: INFO)
  id: string,          // Optional: Finding ID (auto-generated)
  target: string,      // Optional: Target URL/resource
  evidence: string,    // Optional: Proof/evidence
  metadata: object,    // Optional: Additional metadata
}
```

**Example:**
```javascript
await ctx.emitFinding({
  type: 'sql-injection',
  message: 'Potential SQL injection vulnerability detected',
  severity: Severity.CRITICAL,
  target: 'https://example.com/api/users?id=1',
  evidence: 'Parameter "id" is vulnerable to SQL injection',
  metadata: {
    parameter: 'id',
    payload: "' OR '1'='1",
  },
});
```

#### `ctx.log(level, message, data)`

Log a message.

**Parameters:**
- `level` (string) - Log level: 'info', 'warn', 'error'
- `message` (string) - Log message
- `data` (object) - Additional data

**Example:**
```javascript
ctx.log('info', 'Processing HTTP response', { url: 'https://example.com' });
ctx.log('error', 'Failed to parse response', { error: err.message });
```

### Constants

#### Severity Levels

```javascript
const { Severity } = require('../../sdk/plugin-sdk');

Severity.INFO      // 1
Severity.LOW       // 2
Severity.MEDIUM    // 3
Severity.HIGH      // 4
Severity.CRITICAL  // 5
```

#### Capabilities

```javascript
const { Capability } = require('../../sdk/plugin-sdk');

Capability.EMIT_FINDINGS      // Emit findings to host
Capability.HTTP_PASSIVE       // Receive passive HTTP events
Capability.AI_ANALYSIS        // Access AI analysis
Capability.FLOW_INSPECT       // Access sanitized flow events
Capability.FLOW_INSPECT_RAW   // Access raw flow events
Capability.WORKSPACE_READ     // Read from workspace
Capability.WORKSPACE_WRITE    // Write to workspace
Capability.NET_OUTBOUND       // Make outbound requests
Capability.SECRETS_READ       // Read secrets
```

#### Subscriptions

```javascript
const { Subscription } = require('../../sdk/plugin-sdk');

Subscription.FLOW_RESPONSE      // HTTP responses
Subscription.FLOW_REQUEST       // HTTP requests
Subscription.FLOW_RESPONSE_RAW  // Raw HTTP responses
Subscription.FLOW_REQUEST_RAW   // Raw HTTP requests
```

## Hook Reference

### onStart

Called once when the plugin starts.

```javascript
onStart: async ({ ctx, config }) => {
  // Initialize plugin
  ctx.log('info', 'Plugin initialized');
}
```

**Context:**
- `ctx` (Context) - Plugin context
- `config` (object) - Plugin configuration

### onHTTPPassive

Called for each HTTP response event.

```javascript
onHTTPPassive: async ({ ctx, event }) => {
  const response = event.response;

  // Analyze response
  if (response) {
    console.log('Status:', response.statusLine);
    console.log('Headers:', response.headers);
    console.log('Body:', response.body.toString());
  }
}
```

**Context:**
- `ctx` (Context) - Plugin context
- `event.raw` (Buffer) - Raw HTTP data
- `event.response` (object) - Parsed HTTP response
  - `statusLine` (string) - HTTP status line
  - `headers` (object) - Response headers
  - `body` (Buffer) - Response body

### onHTTPActive

Called for active HTTP scanning.

```javascript
onHTTPActive: async ({ ctx, event }) => {
  const request = event.request;

  // Analyze or modify request
  if (request) {
    console.log('Method:', request.method);
    console.log('URL:', request.url);
  }
}
```

**Context:**
- `ctx` (Context) - Plugin context
- `event.raw` (Buffer) - Raw HTTP data
- `event.request` (object) - Parsed HTTP request
  - `method` (string) - HTTP method
  - `url` (string) - Request URL
  - `version` (string) - HTTP version
  - `headers` (object) - Request headers
  - `body` (Buffer) - Request body

## Environment Variables

The plugin SDK requires these environment variables to be set by the host:

- `OXGEN_PLUGIN_HOST` - gRPC host address (default: localhost:50051)
- `OXGEN_AUTH_TOKEN` - Authentication token (required)
- `OXGEN_CAPABILITY_TOKEN` - Capability token (required)

These are automatically provided when the plugin is launched by the 0xGen platform.

## Error Handling

```javascript
register({
  name: 'my-plugin',

  onHTTPPassive: async ({ ctx, event }) => {
    try {
      // Plugin logic
      await ctx.emitFinding({
        type: 'test',
        message: 'Test finding',
      });
    } catch (error) {
      ctx.log('error', 'Failed to process event', {
        error: error.message,
        stack: error.stack,
      });
    }
  },
});
```

## TypeScript Support

The SDK includes TypeScript definitions:

```typescript
import { register, Severity, Capability, Context, Finding } from '../../sdk/plugin-sdk';

interface PluginConfig {
  apiKey: string;
  threshold: number;
}

register({
  name: 'typescript-plugin',

  onStart: async ({ ctx, config }: { ctx: Context; config: PluginConfig }) => {
    ctx.log('info', 'TypeScript plugin started');
  },

  onHTTPPassive: async ({ ctx, event }) => {
    const finding: Finding = {
      type: 'test-finding',
      message: 'Test from TypeScript',
      severity: Severity.INFO,
    };

    await ctx.emitFinding(finding);
  },
});
```

## Plugin Lifecycle

1. **Initialization**: Plugin process starts, SDK connects to host via gRPC
2. **Handshake**: SDK sends Hello message with capabilities and subscriptions
3. **onStart Hook**: Called once after successful connection
4. **Event Loop**: SDK receives events and calls appropriate hooks
5. **Shutdown**: Plugin receives SIGINT/SIGTERM and gracefully shuts down

## Best Practices

### 1. Handle Errors Gracefully

```javascript
onHTTPPassive: async ({ ctx, event }) => {
  try {
    // Your logic here
  } catch (error) {
    ctx.log('error', 'Error in passive hook', { error: error.message });
    // Don't throw - let plugin continue processing other events
  }
}
```

### 2. Use Appropriate Severity Levels

- `CRITICAL` - Exploitable vulnerabilities (SQL injection, RCE)
- `HIGH` - Security issues requiring immediate attention
- `MEDIUM` - Security weaknesses that should be fixed
- `LOW` - Minor security concerns
- `INFO` - Informational findings

### 3. Include Detailed Evidence

```javascript
await ctx.emitFinding({
  type: 'xss-vulnerability',
  message: 'Reflected XSS vulnerability in search parameter',
  severity: Severity.HIGH,
  target: 'https://example.com/search?q=test',
  evidence: 'Payload: <script>alert(1)</script>\nReflected in: <div>test</div>',
  metadata: {
    parameter: 'q',
    payload: '<script>alert(1)</script>',
    injection_point: 'div.search-results',
  },
});
```

### 4. Log Important Events

```javascript
ctx.log('info', 'Analyzing response', { url: targetUrl });
ctx.log('warn', 'Unusual response detected', { status: 999 });
ctx.log('error', 'Failed to parse body', { error: err.message });
```

## Examples

See the `/plugins` directory for complete plugin examples:

- `excavator` - Web crawler plugin
- `seer` - Secrets detection
- `cryptographer` - Cryptographic analysis
- `ranker` - Finding prioritization

## Troubleshooting

### "OXGEN_AUTH_TOKEN environment variable is required"

The plugin must be launched by the 0xGen platform, which sets these variables. Don't run plugins directly.

### "Failed to load protobuf definitions"

Ensure the plugin is run from the correct directory with access to `/proto/oxg/` protobuf files.

### "Missing capability: CAP_EMIT_FINDINGS"

Add the required capability to your plugin configuration:

```javascript
register({
  name: 'my-plugin',
  capabilities: [Capability.EMIT_FINDINGS],
  ...
});
```

## Contributing

See the main 0xGen repository for contribution guidelines.

## License

MIT
