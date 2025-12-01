/**
 * Simple Example Plugin
 *
 * This example demonstrates:
 * - Basic plugin structure
 * - onStart hook
 * - onHTTPPassive hook
 * - Emitting findings
 * - Logging
 */

const { register, Severity, Capability } = require('../index');

register({
  name: 'simple-example',
  capabilities: [Capability.EMIT_FINDINGS, Capability.HTTP_PASSIVE],

  // Called once when plugin starts
  onStart: async ({ ctx, config }) => {
    ctx.log('info', 'Simple example plugin started');

    // Emit an informational finding
    await ctx.emitFinding({
      type: 'plugin-initialized',
      message: 'Simple example plugin is now running',
      severity: Severity.INFO,
    });
  },

  // Called for each HTTP response
  onHTTPPassive: async ({ ctx, event }) => {
    const response = event.response;

    if (!response) {
      return;
    }

    ctx.log('info', 'Processing HTTP response', {
      status: response.statusLine,
    });

    // Example check: Look for missing security headers
    const requiredHeaders = [
      'strict-transport-security',
      'x-frame-options',
      'x-content-type-options',
    ];

    for (const headerName of requiredHeaders) {
      if (!response.headers[headerName]) {
        await ctx.emitFinding({
          type: 'missing-security-header',
          message: `Missing recommended security header: ${headerName}`,
          severity: Severity.LOW,
          metadata: {
            header: headerName,
            status: response.statusLine,
          },
        });
      }
    }

    // Example check: Look for potential sensitive data in response
    const bodyText = response.body.toString('utf-8').toLowerCase();
    const sensitiveKeywords = ['password', 'api_key', 'secret', 'token'];

    for (const keyword of sensitiveKeywords) {
      if (bodyText.includes(keyword)) {
        await ctx.emitFinding({
          type: 'potential-sensitive-data',
          message: `Response may contain sensitive data (keyword: ${keyword})`,
          severity: Severity.MEDIUM,
          evidence: `Found keyword "${keyword}" in response body`,
          metadata: {
            keyword,
          },
        });
        break; // Only emit once per response
      }
    }
  },
});
