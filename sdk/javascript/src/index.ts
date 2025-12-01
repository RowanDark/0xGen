/**
 * 0xGen JavaScript SDK
 *
 * A comprehensive TypeScript/JavaScript SDK for interacting with the 0xGen Security Scanner API.
 *
 * @packageDocumentation
 */

// Export main client
export { OxGenClient, OxGenAPIError } from './client';

// Export all types
export * from './types';

// Export utilities
export {
  waitForScan,
  waitForScans,
  withRetry,
  scanAndWait,
  sleep,
  calculateProgress,
  formatScanDuration,
  groupFindingsBySeverity,
  filterBySeverity,
  isTerminalState,
  isActiveState,
} from './utils';
