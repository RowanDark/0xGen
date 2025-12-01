/**
 * Basic Scan Example
 *
 * This example demonstrates how to:
 * 1. Create a client
 * 2. Start a scan
 * 3. Monitor its progress
 * 4. Get the results
 */

const { OxGenClient, waitForScan } = require('../dist');

async function main() {
  // Initialize client
  const client = new OxGenClient({
    baseURL: process.env.OXGEN_API_URL || 'http://localhost:8080',
    apiKey: process.env.OXGEN_API_KEY,
  });

  try {
    console.log('Creating scan...');

    // Create a new scan
    const response = await client.createScan({
      plugin: 'excavator',
    });

    console.log(`✓ Scan created: ${response.scan_id}`);
    console.log(`  Status: ${response.status}\n`);

    // Wait for scan to complete with progress updates
    console.log('Waiting for scan to complete...');
    const scan = await waitForScan(client, response.scan_id, {
      timeout: 300000, // 5 minutes
      interval: 2000, // Check every 2 seconds
      onProgress: (scan) => {
        console.log(`  [${new Date().toISOString()}] Status: ${scan.status}`);
        if (scan.logs && scan.logs.length > 0) {
          const latestLog = scan.logs[scan.logs.length - 1];
          console.log(`    Log: ${latestLog}`);
        }
      },
    });

    console.log('\n✓ Scan completed!');
    console.log(`  Started: ${scan.started_at}`);
    console.log(`  Completed: ${scan.completed_at}`);

    // Get scan results
    console.log('\nFetching results...');
    const results = await client.getScanResults(response.scan_id);

    console.log(`\n✓ Results retrieved!`);
    console.log(`  Plugin: ${results.plugin}`);
    console.log(`  Generated: ${results.generated_at}`);
    console.log(`  Findings: ${results.findings.length}`);

    // Display findings summary
    if (results.findings.length > 0) {
      console.log('\nFindings Summary:');
      const bySeverity = {};
      results.findings.forEach((f) => {
        bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      });

      Object.entries(bySeverity).forEach(([severity, count]) => {
        console.log(`  ${severity}: ${count}`);
      });

      console.log('\nTop 5 Findings:');
      results.findings.slice(0, 5).forEach((finding, i) => {
        console.log(`  ${i + 1}. [${finding.severity}] ${finding.title}`);
        console.log(`     URL: ${finding.url}`);
      });
    } else {
      console.log('\n✓ No findings detected!');
    }
  } catch (error) {
    console.error('\n✗ Error:', error.message);
    if (error.status) {
      console.error(`  Status Code: ${error.status}`);
    }
    if (error.details) {
      console.error(`  Details:`, error.details);
    }
    process.exit(1);
  }
}

main();
