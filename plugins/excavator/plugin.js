// plugins/excavator/plugin.js
const { register } = require('../../sdk/plugin-sdk');

register({
  name: 'excavator',
  onStart: async ({ emitFinding, config }) => {
    // TODO: orchestrate Playwright-driven crawls and summarize results
    return;
  },
  onHTTPPassive: async ({ request, response, emitFinding }) => {
    // TODO: correlate passive responses with crawler discoveries
    return;
  },
  onHTTPActive: async ({ request, response, emitFinding }) => {
    // TODO: enrich crawler sessions with active checks when required
    return;
  }
});
