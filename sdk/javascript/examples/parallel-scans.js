/**
 * Parallel Scans Example
 *
 * This example demonstrates how to:
 * 1. Start multiple scans simultaneously
 * 2. Monitor them in parallel
 * 3. Aggregate results
 */

const { OxGenClient, waitForScans, groupFindingsBySeverity } = require('../dist');

async function main() {
  const client = new OxGenClient({
    baseURL: process.env.OXGEN_API_URL || 'http://localhost:8080',
    apiKey: process.env.OXGEN_API_KEY,
  });

  try {
    // Get available plugins
    console.log('Fetching available plugins...');
    const { plugins } = await client.listPlugins();
    console.log(`✓ Found ${plugins.length} plugins\n`);

    // Start scans for first 3 plugins
    const pluginsToScan = plugins.slice(0, 3);
    console.log('Starting scans...');

    const scanIds = [];
    for (const plugin of pluginsToScan) {
      const response = await client.createScan({ plugin: plugin.id });
      console.log(`  ✓ ${plugin.name}: ${response.scan_id}`);
      scanIds.push(response.scan_id);
    }

    console.log(`\nWaiting for ${scanIds.length} scans to complete...`);

    // Wait for all scans in parallel
    const scans = await waitForScans(client, scanIds, {
      timeout: 600000, // 10 minutes
      interval: 3000, // Check every 3 seconds
      onProgress: (scan) => {
        console.log(`  [${scan.id.substring(0, 8)}...] ${scan.status}`);
      },
    });

    console.log('\n✓ All scans completed!\n');

    // Collect all results
    console.log('Fetching results...');
    const allResults = await Promise.all(
      scanIds.map(async (id) => {
        try {
          return await client.getScanResults(id);
        } catch (error) {
          console.error(`Failed to get results for ${id}: ${error.message}`);
          return null;
        }
      })
    );

    // Filter out failed results
    const validResults = allResults.filter((r) => r !== null);

    // Aggregate findings
    const allFindings = validResults.flatMap((r) => r.findings);

    console.log('\n=== Summary ===');
    console.log(`Total scans: ${scans.length}`);
    console.log(`Total findings: ${allFindings.length}`);

    // Group by severity
    const grouped = groupFindingsBySeverity(allFindings);
    console.log('\nFindings by severity:');
    console.log(`  Critical: ${grouped.critical.length}`);
    console.log(`  High: ${grouped.high.length}`);
    console.log(`  Medium: ${grouped.medium.length}`);
    console.log(`  Low: ${grouped.low.length}`);
    console.log(`  Info: ${grouped.info.length}`);

    // Show per-plugin breakdown
    console.log('\nPer-plugin breakdown:');
    validResults.forEach((result, i) => {
      const plugin = pluginsToScan[i];
      console.log(`  ${plugin.name}: ${result.findings.length} findings`);
    });

    // Show critical findings
    if (grouped.critical.length > 0) {
      console.log('\n⚠️  Critical Findings:');
      grouped.critical.forEach((finding) => {
        console.log(`  - ${finding.title}`);
        console.log(`    URL: ${finding.url}`);
        console.log(`    Plugin: ${finding.type}`);
      });
    }
  } catch (error) {
    console.error('\n✗ Error:', error.message);
    if (error.status) {
      console.error(`  Status Code: ${error.status}`);
    }
    process.exit(1);
  }
}

main();
