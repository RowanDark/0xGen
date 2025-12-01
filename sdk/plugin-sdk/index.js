/**
 * 0xGen Plugin SDK for Node.js
 *
 * This SDK allows JavaScript/Node.js plugins to integrate with the 0xGen
 * security scanner platform via gRPC.
 */

const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const path = require('path');
const crypto = require('crypto');

// Severity levels
const Severity = {
  INFO: 1,
  LOW: 2,
  MEDIUM: 3,
  HIGH: 4,
  CRITICAL: 5,
};

// Capabilities
const Capability = {
  EMIT_FINDINGS: 'CAP_EMIT_FINDINGS',
  HTTP_PASSIVE: 'CAP_HTTP_PASSIVE',
  AI_ANALYSIS: 'CAP_AI_ANALYSIS',
  FLOW_INSPECT: 'CAP_FLOW_INSPECT',
  FLOW_INSPECT_RAW: 'CAP_FLOW_INSPECT_RAW',
  WORKSPACE_READ: 'CAP_WORKSPACE_READ',
  WORKSPACE_WRITE: 'CAP_WORKSPACE_WRITE',
  NET_OUTBOUND: 'CAP_NET_OUTBOUND',
  SECRETS_READ: 'CAP_SECRETS_READ',
};

// Subscriptions
const Subscription = {
  FLOW_RESPONSE: 'FLOW_RESPONSE',
  FLOW_REQUEST: 'FLOW_REQUEST',
  FLOW_RESPONSE_RAW: 'FLOW_RESPONSE_RAW',
  FLOW_REQUEST_RAW: 'FLOW_REQUEST_RAW',
};

/**
 * Plugin context providing access to SDK features
 */
class Context {
  constructor(runtime, logger, capabilities, pluginName) {
    this.runtime = runtime;
    this.logger = logger;
    this.capabilities = new Set(capabilities || []);
    this.pluginName = pluginName;
  }

  /**
   * Emit a finding to the host
   * @param {Object} finding - Finding object
   * @param {string} finding.type - Finding type (required)
   * @param {string} finding.message - Finding message (required)
   * @param {number} [finding.severity] - Severity level (default: INFO)
   * @param {string} [finding.id] - Finding ID (auto-generated if not provided)
   * @param {string} [finding.target] - Target URL or resource
   * @param {string} [finding.evidence] - Evidence/proof
   * @param {Object} [finding.metadata] - Additional metadata
   */
  emitFinding(finding) {
    if (!this.capabilities.has(Capability.EMIT_FINDINGS)) {
      throw new Error(`Missing capability: ${Capability.EMIT_FINDINGS}`);
    }

    if (!finding.type || typeof finding.type !== 'string' || !finding.type.trim()) {
      throw new Error('Finding type is required and must be a non-empty string');
    }

    if (!finding.message || typeof finding.message !== 'string' || !finding.message.trim()) {
      throw new Error('Finding message is required and must be a non-empty string');
    }

    const findingId = finding.id?.trim()?.toUpperCase() || generateULID();
    const severity = finding.severity || Severity.INFO;
    const detectedAt = finding.detectedAt || new Date();

    const metadata = { ...(finding.metadata || {}) };
    metadata.id = findingId;

    if (finding.target?.trim()) {
      metadata.target = finding.target.trim();
    }

    if (finding.evidence?.trim()) {
      metadata.evidence = finding.evidence.trim();
    }

    metadata.detected_at = detectedAt.toISOString();

    const pbFinding = {
      type: finding.type.trim(),
      message: finding.message.trim(),
      severity,
      metadata,
    };

    return this.runtime.sendFinding(pbFinding);
  }

  /**
   * Log a message
   * @param {string} level - Log level (info, warn, error)
   * @param {string} message - Log message
   * @param {Object} [data] - Additional data
   */
  log(level, message, data) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      plugin: this.pluginName,
      message,
      ...(data || {}),
    };

    if (this.logger) {
      this.logger(logEntry);
    } else {
      console.log(JSON.stringify(logEntry));
    }
  }
}

/**
 * Runtime state managing plugin lifecycle
 */
class Runtime {
  constructor(stream) {
    this.stream = stream;
    this.sendMutex = false;
  }

  async sendFinding(finding) {
    // Simple mutex to prevent concurrent sends
    while (this.sendMutex) {
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    this.sendMutex = true;
    try {
      return new Promise((resolve, reject) => {
        this.stream.write(
          {
            finding,
          },
          (error) => {
            if (error) {
              reject(error);
            } else {
              resolve();
            }
          }
        );
      });
    } finally {
      this.sendMutex = false;
    }
  }
}

/**
 * Generate a ULID-like identifier
 */
function generateULID() {
  const timestamp = Date.now();
  const randomBytes = crypto.randomBytes(10);
  const combined = Buffer.alloc(16);

  // Write timestamp (6 bytes, big-endian)
  combined.writeUIntBE(timestamp, 0, 6);
  // Write random bytes (10 bytes)
  randomBytes.copy(combined, 6);

  // Base32 encode using Crockford alphabet
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let result = '';

  // Convert to base32
  for (let i = 0; i < 26; i++) {
    const byteIndex = Math.floor(i * 5 / 8);
    const bitIndex = (i * 5) % 8;

    let value;
    if (bitIndex <= 3) {
      value = (combined[byteIndex] >> (3 - bitIndex)) & 0x1F;
    } else {
      value = ((combined[byteIndex] << (bitIndex - 3)) & 0x1F);
      if (byteIndex + 1 < combined.length) {
        value |= (combined[byteIndex + 1] >> (11 - bitIndex));
      }
    }

    result += alphabet[value];
  }

  return result;
}

/**
 * Load protobuf definitions
 */
function loadProtos() {
  const PROTO_PATH = path.join(__dirname, '../../proto/oxg/plugin_bus.proto');
  const COMMON_PATH = path.join(__dirname, '../../proto/oxg/common.proto');

  const packageDefinition = protoLoader.loadSync(
    [PROTO_PATH, COMMON_PATH],
    {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
      includeDirs: [path.join(__dirname, '../../proto')],
    }
  );

  return grpc.loadPackageDefinition(packageDefinition);
}

/**
 * Main plugin registration function
 * @param {Object} config - Plugin configuration
 * @param {string} config.name - Plugin name
 * @param {Function} [config.onStart] - Called when plugin starts
 * @param {Function} [config.onHTTPPassive] - Called for passive HTTP events
 * @param {Function} [config.onHTTPActive] - Called for active HTTP events
 * @param {Array<string>} [config.capabilities] - Required capabilities
 * @param {Array<string>} [config.subscriptions] - Event subscriptions
 * @param {Function} [config.logger] - Custom logger function
 */
async function register(config) {
  // Validate config
  if (!config || !config.name) {
    throw new Error('Plugin name is required');
  }

  // Get connection parameters from environment
  const host = process.env.OXGEN_PLUGIN_HOST || 'localhost:50051';
  const authToken = process.env.OXGEN_AUTH_TOKEN;
  const capabilityToken = process.env.OXGEN_CAPABILITY_TOKEN;
  const pluginName = config.name;

  if (!authToken) {
    throw new Error('OXGEN_AUTH_TOKEN environment variable is required');
  }

  if (!capabilityToken) {
    throw new Error('OXGEN_CAPABILITY_TOKEN environment variable is required');
  }

  // Determine capabilities and subscriptions
  const capabilities = config.capabilities || [];
  const subscriptions = config.subscriptions || [];

  // Auto-add capabilities based on hooks
  if (config.onHTTPPassive) {
    if (!capabilities.includes(Capability.HTTP_PASSIVE)) {
      capabilities.push(Capability.HTTP_PASSIVE);
    }
    if (!capabilities.includes(Capability.FLOW_INSPECT)) {
      capabilities.push(Capability.FLOW_INSPECT);
    }
    if (!subscriptions.includes(Subscription.FLOW_RESPONSE)) {
      subscriptions.push(Subscription.FLOW_RESPONSE);
    }
  }

  // Load gRPC service
  let proto;
  try {
    proto = loadProtos();
  } catch (error) {
    console.error('Failed to load protobuf definitions:', error.message);
    console.error('Make sure the plugin is run from the correct directory');
    throw error;
  }

  const client = new proto.oxg.plugin_bus.PluginBus(
    host,
    grpc.credentials.createInsecure()
  );

  // Create bidirectional stream
  const stream = client.EventStream();

  const runtime = new Runtime(stream);
  const ctx = new Context(runtime, config.logger, capabilities, pluginName);

  // Handle incoming events from host
  stream.on('data', async (hostEvent) => {
    try {
      if (hostEvent.flow_event) {
        const flowEvent = hostEvent.flow_event;

        if (flowEvent.type === 2 && config.onHTTPPassive) {
          // FLOW_RESPONSE event
          const event = {
            raw: flowEvent.data,
            response: parseHTTPResponse(flowEvent.data),
          };

          await config.onHTTPPassive({ ctx, event });
        } else if (flowEvent.type === 1 && config.onHTTPActive) {
          // FLOW_REQUEST event
          const event = {
            raw: flowEvent.data,
            request: parseHTTPRequest(flowEvent.data),
          };

          await config.onHTTPActive({ ctx, event });
        }
      }
    } catch (error) {
      ctx.log('error', 'Error handling host event', { error: error.message, stack: error.stack });
    }
  });

  stream.on('error', (error) => {
    ctx.log('error', 'Stream error', { error: error.message });
    process.exit(1);
  });

  stream.on('end', () => {
    ctx.log('info', 'Stream ended by host');
    process.exit(0);
  });

  // Send hello message
  const hello = {
    hello: {
      auth_token: authToken,
      plugin_name: pluginName,
      pid: process.pid,
      subscriptions,
      capabilities,
      capability_token: capabilityToken,
    },
  };

  stream.write(hello);

  // Call onStart hook if provided
  if (config.onStart) {
    try {
      await config.onStart({ ctx, config: {} });
    } catch (error) {
      ctx.log('error', 'Error in onStart hook', { error: error.message, stack: error.stack });
      process.exit(1);
    }
  }

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    ctx.log('info', 'Received SIGINT, shutting down');
    stream.end();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    ctx.log('info', 'Received SIGTERM, shutting down');
    stream.end();
    process.exit(0);
  });

  return ctx;
}

/**
 * Parse HTTP response from bytes
 */
function parseHTTPResponse(data) {
  if (!data || data.length === 0) {
    return null;
  }

  try {
    const text = data.toString('utf-8');
    const lines = text.split('\r\n');

    if (lines.length === 0) {
      return null;
    }

    const statusLine = lines[0];
    const headers = {};
    let bodyStart = 0;

    // Parse headers
    for (let i = 1; i < lines.length; i++) {
      if (lines[i] === '') {
        bodyStart = i + 1;
        break;
      }

      const colonIndex = lines[i].indexOf(':');
      if (colonIndex > 0) {
        const key = lines[i].substring(0, colonIndex).trim();
        const value = lines[i].substring(colonIndex + 1).trim();
        headers[key.toLowerCase()] = value;
      }
    }

    const body = lines.slice(bodyStart).join('\r\n');

    return {
      statusLine,
      headers,
      body: Buffer.from(body, 'utf-8'),
    };
  } catch (error) {
    return null;
  }
}

/**
 * Parse HTTP request from bytes
 */
function parseHTTPRequest(data) {
  if (!data || data.length === 0) {
    return null;
  }

  try {
    const text = data.toString('utf-8');
    const lines = text.split('\r\n');

    if (lines.length === 0) {
      return null;
    }

    const requestLine = lines[0];
    const [method, url, version] = requestLine.split(' ');
    const headers = {};
    let bodyStart = 0;

    // Parse headers
    for (let i = 1; i < lines.length; i++) {
      if (lines[i] === '') {
        bodyStart = i + 1;
        break;
      }

      const colonIndex = lines[i].indexOf(':');
      if (colonIndex > 0) {
        const key = lines[i].substring(0, colonIndex).trim();
        const value = lines[i].substring(colonIndex + 1).trim();
        headers[key.toLowerCase()] = value;
      }
    }

    const body = lines.slice(bodyStart).join('\r\n');

    return {
      method,
      url,
      version,
      headers,
      body: Buffer.from(body, 'utf-8'),
    };
  } catch (error) {
    return null;
  }
}

// Exports
module.exports = {
  register,
  Severity,
  Capability,
  Subscription,
  Context,
};
