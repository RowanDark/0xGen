import { OxGenClient, OxGenAPIError } from './client';
import { Scan, PollOptions, RetryOptions } from './types';

/**
 * Wait for a scan to complete by polling its status
 * @param client - OxGen API client instance
 * @param scanId - Scan identifier to monitor
 * @param options - Polling configuration options
 * @returns Completed scan information
 * @throws {OxGenAPIError} If scan fails or timeout is reached
 */
export async function waitForScan(
  client: OxGenClient,
  scanId: string,
  options: PollOptions = {}
): Promise<Scan> {
  const timeout = options.timeout || 300000; // 5 minutes default
  const interval = options.interval || 2000; // 2 seconds default
  const startTime = Date.now();

  while (true) {
    // Check if timeout reached
    if (Date.now() - startTime > timeout) {
      throw new OxGenAPIError(
        `Scan timeout: scan ${scanId} did not complete within ${timeout}ms`,
        408
      );
    }

    // Get current scan status
    const scan = await client.getScanStatus(scanId);

    // Call progress callback if provided
    if (options.onProgress) {
      options.onProgress(scan);
    }

    // Check terminal states
    if (scan.status === 'completed') {
      return scan;
    }

    if (scan.status === 'failed') {
      throw new OxGenAPIError(
        `Scan failed: ${scan.error || 'Unknown error'}`,
        500,
        { scan }
      );
    }

    // Wait before polling again
    await sleep(interval);
  }
}

/**
 * Wait for multiple scans to complete
 * @param client - OxGen API client instance
 * @param scanIds - Array of scan identifiers to monitor
 * @param options - Polling configuration options
 * @returns Array of completed scan information
 */
export async function waitForScans(
  client: OxGenClient,
  scanIds: string[],
  options: PollOptions = {}
): Promise<Scan[]> {
  const promises = scanIds.map((scanId) => waitForScan(client, scanId, options));
  return Promise.all(promises);
}

/**
 * Execute a function with automatic retry on failure
 * @param fn - Async function to execute
 * @param options - Retry configuration options
 * @returns Result of the function
 * @throws Last error if all retries fail
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const maxRetries = options.maxRetries || 3;
  const initialDelay = options.initialDelay || 1000;
  const maxDelay = options.maxDelay || 10000;
  const backoffMultiplier = options.backoffMultiplier || 2;

  let lastError: Error;
  let delay = initialDelay;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      // Don't retry on client errors (4xx except 408 timeout and 429 rate limit)
      if (error instanceof OxGenAPIError) {
        const status = error.status;
        if (status >= 400 && status < 500 && status !== 408 && status !== 429) {
          throw error;
        }
      }

      // Don't retry if this was the last attempt
      if (attempt === maxRetries) {
        break;
      }

      // Wait before retrying
      await sleep(delay);

      // Exponential backoff with max delay cap
      delay = Math.min(delay * backoffMultiplier, maxDelay);
    }
  }

  throw lastError!;
}

/**
 * Create a scan and wait for it to complete
 * @param client - OxGen API client instance
 * @param plugin - Plugin name to use
 * @param pollOptions - Polling configuration options
 * @returns Completed scan with results
 */
export async function scanAndWait(
  client: OxGenClient,
  plugin: string,
  pollOptions: PollOptions = {}
): Promise<{ scan: Scan; results: any }> {
  // Create scan
  const createResponse = await client.createScan({ plugin });

  // Wait for completion
  const scan = await waitForScan(client, createResponse.scan_id, pollOptions);

  // Get results
  const results = await client.getScanResults(createResponse.scan_id);

  return { scan, results };
}

/**
 * Sleep for a specified duration
 * @param ms - Duration in milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Calculate scan progress percentage
 * @param scan - Scan information
 * @returns Progress percentage (0-100)
 */
export function calculateProgress(scan: Scan): number {
  switch (scan.status) {
    case 'pending':
      return 0;
    case 'running':
      return 50;
    case 'completed':
    case 'failed':
      return 100;
    default:
      return 0;
  }
}

/**
 * Format scan duration in human-readable format
 * @param scan - Scan information
 * @returns Duration string (e.g., "2m 34s")
 */
export function formatScanDuration(scan: Scan): string {
  if (!scan.started_at) {
    return 'Not started';
  }

  const start = new Date(scan.started_at).getTime();
  const end = scan.completed_at
    ? new Date(scan.completed_at).getTime()
    : Date.now();
  const durationMs = end - start;

  const seconds = Math.floor(durationMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  } else {
    return `${seconds}s`;
  }
}

/**
 * Group findings by severity
 * @param findings - Array of findings
 * @returns Findings grouped by severity
 */
export function groupFindingsBySeverity(findings: any[]): Record<string, any[]> {
  const grouped: Record<string, any[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: [],
  };

  for (const finding of findings) {
    const severity = finding.severity || 'info';
    if (grouped[severity]) {
      grouped[severity].push(finding);
    } else {
      grouped.info.push(finding);
    }
  }

  return grouped;
}

/**
 * Filter findings by minimum severity
 * @param findings - Array of findings
 * @param minSeverity - Minimum severity level to include
 * @returns Filtered findings
 */
export function filterBySeverity(
  findings: any[],
  minSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info'
): any[] {
  const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
  const minIndex = severityOrder.indexOf(minSeverity);

  return findings.filter((finding) => {
    const severity = finding.severity || 'info';
    const index = severityOrder.indexOf(severity);
    return index >= minIndex;
  });
}

/**
 * Check if scan is in terminal state (completed or failed)
 * @param scan - Scan information
 * @returns True if scan is in terminal state
 */
export function isTerminalState(scan: Scan): boolean {
  return scan.status === 'completed' || scan.status === 'failed';
}

/**
 * Check if scan is active (pending or running)
 * @param scan - Scan information
 * @returns True if scan is active
 */
export function isActiveState(scan: Scan): boolean {
  return scan.status === 'pending' || scan.status === 'running';
}
