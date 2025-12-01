/**
 * Type definitions for 0xGen API SDK
 */

/**
 * Scan status values
 */
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';

/**
 * Team member roles
 */
export type Role = 'admin' | 'analyst' | 'viewer';

/**
 * Finding severity levels
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Finding confidence levels
 */
export type Confidence = 'confirmed' | 'firm' | 'tentative';

/**
 * Configuration for creating a scan
 */
export interface CreateScanRequest {
  /** Plugin name to use for scanning */
  plugin: string;
}

/**
 * Response when creating a scan
 */
export interface CreateScanResponse {
  /** Unique scan identifier */
  scan_id: string;
  /** Current scan status */
  status: ScanStatus;
}

/**
 * Detailed scan information
 */
export interface Scan {
  /** Unique scan identifier */
  id: string;
  /** Plugin used for this scan */
  plugin: string;
  /** Current scan status */
  status: ScanStatus;
  /** Timestamp when scan was created */
  created_at: string;
  /** Timestamp when scan started (null if not started) */
  started_at: string | null;
  /** Timestamp when scan completed (null if not completed) */
  completed_at: string | null;
  /** Error message if scan failed (null if no error) */
  error: string | null;
  /** Scan execution logs */
  logs: string[];
}

/**
 * Security finding from a scan
 */
export interface Finding {
  /** Unique finding identifier */
  id: string;
  /** Finding type/category */
  type: string;
  /** Severity level */
  severity: Severity;
  /** Confidence level */
  confidence: Confidence;
  /** Finding title */
  title: string;
  /** Detailed description */
  description: string;
  /** URL where finding was discovered */
  url: string;
  /** Parameter name if applicable */
  parameter?: string;
  /** Proof of concept or evidence */
  proof: string;
  /** Remediation guidance */
  remediation: string;
}

/**
 * Scan results including findings
 */
export interface ScanResult {
  /** Scan identifier */
  scan_id: string;
  /** Plugin that generated results */
  plugin: string;
  /** Timestamp when results were generated */
  generated_at: string;
  /** List of findings discovered */
  findings: Finding[];
  /** Digital signature of results */
  signature: string;
  /** Digest/hash of results */
  digest: string;
}

/**
 * Plugin information
 */
export interface Plugin {
  /** Plugin identifier */
  id: string;
  /** Display name */
  name: string;
  /** Plugin version */
  version: string;
  /** Plugin description */
  description: string;
  /** Plugin capabilities */
  capabilities?: string[];
}

/**
 * List of available plugins
 */
export interface ListPluginsResponse {
  plugins: Plugin[];
}

/**
 * Request to issue an API token
 */
export interface TokenRequest {
  /** Subject/user identifier */
  subject: string;
  /** Token audience */
  audience?: string;
  /** Token time-to-live in seconds */
  ttl_seconds?: number;
  /** Workspace identifier */
  workspace_id?: string;
  /** Role to assign */
  role?: Role;
}

/**
 * API token response
 */
export interface TokenResponse {
  /** JWT token */
  token: string;
  /** Token expiration timestamp (RFC3339) */
  expires_at: string;
}

/**
 * API error response
 */
export interface APIError {
  /** Error message */
  message: string;
  /** HTTP status code */
  status: number;
  /** Additional error details */
  details?: any;
}

/**
 * Client configuration options
 */
export interface ClientConfig {
  /** Base URL of the 0xGen API (e.g., https://api.0xgen.com) */
  baseURL: string;
  /** API authentication token */
  apiKey?: string;
  /** Static management token for token issuance */
  staticToken?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Custom headers to include in all requests */
  headers?: Record<string, string>;
}

/**
 * Options for polling operations
 */
export interface PollOptions {
  /** Maximum time to poll in milliseconds (default: 300000 / 5 minutes) */
  timeout?: number;
  /** Interval between poll requests in milliseconds (default: 2000) */
  interval?: number;
  /** Callback invoked on each poll attempt */
  onProgress?: (scan: Scan) => void;
}

/**
 * Options for retry operations
 */
export interface RetryOptions {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  /** Initial delay between retries in milliseconds (default: 1000) */
  initialDelay?: number;
  /** Maximum delay between retries in milliseconds (default: 10000) */
  maxDelay?: number;
  /** Multiplier for exponential backoff (default: 2) */
  backoffMultiplier?: number;
}

/**
 * Cipher operation execution request
 */
export interface CipherExecuteRequest {
  /** Input data to process */
  input: string;
  /** Operation to perform */
  operation: string;
  /** Operation parameters */
  params?: Record<string, any>;
}

/**
 * Cipher operation execution response
 */
export interface CipherExecuteResponse {
  /** Output data */
  output: string;
}

/**
 * Cipher recipe save request
 */
export interface CipherRecipeSaveRequest {
  /** Recipe name */
  name: string;
  /** Recipe operations */
  operations: any[];
}

/**
 * Cipher recipe
 */
export interface CipherRecipe {
  /** Recipe name */
  name: string;
  /** Recipe operations */
  operations: any[];
}
