// plugins/osint-well/plugin.js
const { register } = require('../../sdk/plugin-sdk');

register({
  name: 'osint-well',
  onStart: async ({ emitFinding, config }) => {
    // TODO: prepare Amass orchestration and data normalization
    return;
  },
  onHTTPPassive: async ({ request, response, emitFinding }) => {
    // TODO: optionally correlate passive responses with OSINT data
    return;
  },
  onHTTPActive: async ({ request, response, emitFinding }) => {
    // TODO: drive enrichment lookups when triggered by other plugins
    return;
  }
});
