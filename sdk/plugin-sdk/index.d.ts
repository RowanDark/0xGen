/**
 * TypeScript definitions for 0xGen Plugin SDK
 */

export interface Finding {
  /** Finding type (required) */
  type: string;
  /** Finding message (required) */
  message: string;
  /** Severity level */
  severity?: number;
  /** Finding ID (auto-generated if not provided) */
  id?: string;
  /** Target URL or resource */
  target?: string;
  /** Evidence or proof */
  evidence?: string;
  /** Additional metadata */
  metadata?: Record<string, string>;
  /** Detection timestamp */
  detectedAt?: Date;
}

export interface LogEntry {
  timestamp: string;
  level: string;
  plugin: string;
  message: string;
  [key: string]: any;
}

export interface HTTPResponse {
  statusLine: string;
  headers: Record<string, string>;
  body: Buffer;
}

export interface HTTPRequest {
  method: string;
  url: string;
  version: string;
  headers: Record<string, string>;
  body: Buffer;
}

export interface HTTPPassiveEvent {
  raw: Buffer;
  response: HTTPResponse | null;
}

export interface HTTPActiveEvent {
  raw: Buffer;
  request: HTTPRequest | null;
}

export declare class Context {
  constructor(
    runtime: any,
    logger: ((entry: LogEntry) => void) | null,
    capabilities: string[],
    pluginName: string
  );

  runtime: any;
  logger: ((entry: LogEntry) => void) | null;
  capabilities: Set<string>;
  pluginName: string;

  /**
   * Emit a finding to the host
   */
  emitFinding(finding: Finding): Promise<void>;

  /**
   * Log a message
   */
  log(level: string, message: string, data?: any): void;
}

export interface OnStartContext {
  /** Plugin context */
  ctx: Context;
  /** Plugin configuration */
  config: Record<string, any>;
}

export interface OnHTTPPassiveContext {
  /** Plugin context */
  ctx: Context;
  /** HTTP passive event */
  event: HTTPPassiveEvent;
}

export interface OnHTTPActiveContext {
  /** Plugin context */
  ctx: Context;
  /** HTTP active event */
  event: HTTPActiveEvent;
}

export interface PluginConfig {
  /** Plugin name (required) */
  name: string;
  /** Called when plugin starts */
  onStart?: (context: OnStartContext) => void | Promise<void>;
  /** Called for passive HTTP events */
  onHTTPPassive?: (context: OnHTTPPassiveContext) => void | Promise<void>;
  /** Called for active HTTP events */
  onHTTPActive?: (context: OnHTTPActiveContext) => void | Promise<void>;
  /** Required capabilities */
  capabilities?: string[];
  /** Event subscriptions */
  subscriptions?: string[];
  /** Custom logger function */
  logger?: (entry: LogEntry) => void;
}

/**
 * Register a plugin with the 0xGen platform
 */
export declare function register(config: PluginConfig): Promise<Context>;

/**
 * Severity levels
 */
export declare const Severity: {
  INFO: 1;
  LOW: 2;
  MEDIUM: 3;
  HIGH: 4;
  CRITICAL: 5;
};

/**
 * Plugin capabilities
 */
export declare const Capability: {
  EMIT_FINDINGS: 'CAP_EMIT_FINDINGS';
  HTTP_PASSIVE: 'CAP_HTTP_PASSIVE';
  AI_ANALYSIS: 'CAP_AI_ANALYSIS';
  FLOW_INSPECT: 'CAP_FLOW_INSPECT';
  FLOW_INSPECT_RAW: 'CAP_FLOW_INSPECT_RAW';
  WORKSPACE_READ: 'CAP_WORKSPACE_READ';
  WORKSPACE_WRITE: 'CAP_WORKSPACE_WRITE';
  NET_OUTBOUND: 'CAP_NET_OUTBOUND';
  SECRETS_READ: 'CAP_SECRETS_READ';
};

/**
 * Event subscriptions
 */
export declare const Subscription: {
  FLOW_RESPONSE: 'FLOW_RESPONSE';
  FLOW_REQUEST: 'FLOW_REQUEST';
  FLOW_RESPONSE_RAW: 'FLOW_RESPONSE_RAW';
  FLOW_REQUEST_RAW: 'FLOW_REQUEST_RAW';
};
