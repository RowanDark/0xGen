/**
 * Security Header Scanner Plugin
 *
 * This plugin checks HTTP responses for missing or misconfigured
 * security headers.
 */

const { register, Severity, Capability } = require('../index');

// Security header best practices
const SECURITY_HEADERS = {
  'strict-transport-security': {
    required: true,
    severity: Severity.HIGH,
    message: 'Missing Strict-Transport-Security header',
    description: 'HSTS header protects against protocol downgrade attacks',
  },
  'x-frame-options': {
    required: true,
    severity: Severity.MEDIUM,
    message: 'Missing X-Frame-Options header',
    description: 'Protects against clickjacking attacks',
  },
  'x-content-type-options': {
    required: true,
    severity: Severity.MEDIUM,
    message: 'Missing X-Content-Type-Options header',
    description: 'Prevents MIME type sniffing',
  },
  'content-security-policy': {
    required: true,
    severity: Severity.MEDIUM,
    message: 'Missing Content-Security-Policy header',
    description: 'Helps prevent XSS and injection attacks',
  },
  'x-xss-protection': {
    required: false,
    severity: Severity.LOW,
    message: 'Missing X-XSS-Protection header',
    description: 'Enables browser XSS protection',
  },
  'referrer-policy': {
    required: false,
    severity: Severity.LOW,
    message: 'Missing Referrer-Policy header',
    description: 'Controls referrer information sent',
  },
  'permissions-policy': {
    required: false,
    severity: Severity.LOW,
    message: 'Missing Permissions-Policy header',
    description: 'Controls browser features and APIs',
  },
};

register({
  name: 'header-scanner',
  capabilities: [Capability.EMIT_FINDINGS, Capability.HTTP_PASSIVE],

  onStart: async ({ ctx }) => {
    ctx.log('info', 'Security header scanner initialized', {
      headers_to_check: Object.keys(SECURITY_HEADERS).length,
    });
  },

  onHTTPPassive: async ({ ctx, event }) => {
    const response = event.response;
    if (!response) return;

    const headers = response.headers;
    const statusLine = response.statusLine;

    // Extract status code
    const statusMatch = statusLine.match(/\d{3}/);
    const statusCode = statusMatch ? parseInt(statusMatch[0]) : 0;

    // Only check successful responses (2xx)
    if (statusCode < 200 || statusCode >= 300) {
      return;
    }

    // Check each security header
    for (const [headerName, config] of Object.entries(SECURITY_HEADERS)) {
      if (!headers[headerName]) {
        await ctx.emitFinding({
          type: 'missing-security-header',
          message: config.message,
          severity: config.severity,
          evidence: config.description,
          metadata: {
            header: headerName,
            required: config.required.toString(),
            status_code: statusCode.toString(),
          },
        });
      }
    }

    // Check for insecure header values
    if (headers['strict-transport-security']) {
      const hsts = headers['strict-transport-security'];
      if (!hsts.includes('max-age=')) {
        await ctx.emitFinding({
          type: 'weak-hsts-configuration',
          message: 'HSTS header missing max-age directive',
          severity: Severity.MEDIUM,
          evidence: `Current value: ${hsts}`,
        });
      }
    }

    if (headers['x-frame-options']) {
      const xfo = headers['x-frame-options'].toUpperCase();
      if (!['DENY', 'SAMEORIGIN'].includes(xfo)) {
        await ctx.emitFinding({
          type: 'weak-frame-options',
          message: 'X-Frame-Options uses weak value',
          severity: Severity.LOW,
          evidence: `Current value: ${headers['x-frame-options']}`,
          metadata: {
            recommendation: 'Use DENY or SAMEORIGIN',
          },
        });
      }
    }
  },
});
