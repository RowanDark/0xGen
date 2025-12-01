/**
 * Error Handling Example
 *
 * This example demonstrates comprehensive error handling:
 * 1. Network errors
 * 2. API errors (4xx, 5xx)
 * 3. Timeout errors
 * 4. Retry logic
 */

const { OxGenClient, OxGenAPIError, withRetry } = require('../dist');

async function main() {
  // Example 1: Basic error handling
  console.log('=== Example 1: Basic Error Handling ===\n');

  const client = new OxGenClient({
    baseURL: process.env.OXGEN_API_URL || 'http://localhost:8080',
    apiKey: process.env.OXGEN_API_KEY,
  });

  try {
    // Try to get a non-existent scan
    await client.getScanStatus('non-existent-scan-id');
  } catch (error) {
    if (error instanceof OxGenAPIError) {
      console.log('✓ Caught OxGenAPIError');
      console.log(`  Status: ${error.status}`);
      console.log(`  Message: ${error.message}`);
      console.log(`  Name: ${error.name}`);
    }
  }

  // Example 2: Handling different status codes
  console.log('\n=== Example 2: Status Code Handling ===\n');

  async function handleAPICall(fn, description) {
    try {
      await fn();
      console.log(`✓ ${description}: Success`);
    } catch (error) {
      if (error instanceof OxGenAPIError) {
        switch (error.status) {
          case 400:
            console.log(`✗ ${description}: Bad Request - ${error.message}`);
            break;
          case 401:
            console.log(`✗ ${description}: Unauthorized - Check your API key`);
            break;
          case 403:
            console.log(`✗ ${description}: Forbidden - Insufficient permissions`);
            break;
          case 404:
            console.log(`✗ ${description}: Not Found`);
            break;
          case 408:
            console.log(`✗ ${description}: Request Timeout`);
            break;
          case 429:
            console.log(`✗ ${description}: Rate Limited`);
            break;
          case 500:
            console.log(`✗ ${description}: Internal Server Error`);
            break;
          default:
            console.log(`✗ ${description}: Error ${error.status}`);
        }
      } else {
        console.log(`✗ ${description}: ${error.message}`);
      }
    }
  }

  await handleAPICall(
    () => client.getScanStatus('invalid-id'),
    'Get invalid scan'
  );

  // Example 3: Timeout handling
  console.log('\n=== Example 3: Timeout Handling ===\n');

  const shortTimeoutClient = new OxGenClient({
    baseURL: process.env.OXGEN_API_URL || 'http://localhost:8080',
    apiKey: process.env.OXGEN_API_KEY,
    timeout: 1, // Very short timeout to trigger error
  });

  try {
    await shortTimeoutClient.listPlugins();
  } catch (error) {
    if (error instanceof OxGenAPIError && error.status === 408) {
      console.log('✓ Timeout detected correctly');
      console.log(`  Message: ${error.message}`);
    }
  }

  // Example 4: Retry logic
  console.log('\n=== Example 4: Automatic Retry ===\n');

  let attemptCount = 0;

  const unreliableOperation = async () => {
    attemptCount++;
    console.log(`  Attempt ${attemptCount}...`);

    // Simulate failure on first 2 attempts
    if (attemptCount < 3) {
      throw new OxGenAPIError('Temporary failure', 503);
    }

    return { success: true };
  };

  try {
    const result = await withRetry(unreliableOperation, {
      maxRetries: 3,
      initialDelay: 500,
      backoffMultiplier: 2,
    });

    console.log('✓ Operation succeeded after retries');
    console.log(`  Total attempts: ${attemptCount}`);
  } catch (error) {
    console.log(`✗ Operation failed after ${attemptCount} attempts`);
  }

  // Example 5: No retry on client errors
  console.log('\n=== Example 5: No Retry on Client Errors ===\n');

  attemptCount = 0;

  const clientErrorOperation = async () => {
    attemptCount++;
    console.log(`  Attempt ${attemptCount}...`);
    throw new OxGenAPIError('Bad Request', 400);
  };

  try {
    await withRetry(clientErrorOperation, {
      maxRetries: 3,
      initialDelay: 500,
    });
  } catch (error) {
    if (error instanceof OxGenAPIError && error.status === 400) {
      console.log('✓ Client error (4xx) not retried');
      console.log(`  Total attempts: ${attemptCount} (should be 1)`);
    }
  }

  // Example 6: Network error handling
  console.log('\n=== Example 6: Network Error Handling ===\n');

  const badClient = new OxGenClient({
    baseURL: 'http://invalid-hostname-that-does-not-exist:9999',
    apiKey: 'test',
    timeout: 5000,
  });

  try {
    await badClient.healthCheck();
  } catch (error) {
    if (error instanceof OxGenAPIError) {
      console.log('✓ Network error caught');
      console.log(`  Status: ${error.status} (0 indicates network error)`);
      console.log(`  Message: ${error.message}`);
    }
  }

  console.log('\n=== All examples completed ===\n');
}

main();
