// plugins/cryptographer/plugin.js
const { register } = require('../../sdk/plugin-sdk');

register({
  name: 'cryptographer',
  onStart: async ({ emitFinding, config }) => {
    // TODO: expose transformation utilities through the UI
    return;
  },
  onHTTPPassive: async ({ request, response, emitFinding }) => {
    // This utility plugin does not consume passive HTTP data yet.
    return;
  },
  onHTTPActive: async ({ request, response, emitFinding }) => {
    // Active hooks are not required for the UI skeleton.
    return;
  }
});
