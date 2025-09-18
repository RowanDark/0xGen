// plugins/galdr-proxy/plugin.js
const { register } = require('../../sdk/plugin-sdk');

register({
  name: 'galdr-proxy',
  onStart: async ({ emitFinding, config }) => {
    // TODO: initialize proxy integrations
    return;
  },
  onHTTPPassive: async ({ request, response, emitFinding }) => {
    // TODO: observe passive traffic and emit findings when relevant
    return;
  },
  onHTTPActive: async ({ request, response, emitFinding }) => {
    // TODO: manage active proxy interactions
    return;
  }
});
