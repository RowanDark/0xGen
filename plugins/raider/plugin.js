// plugins/raider/plugin.js
const { register } = require('../../sdk/plugin-sdk');

register({
  name: 'raider',
  onStart: async ({ emitFinding, config }) => {
    // TODO: queue active campaigns and seed reconnaissance data
    return;
  },
  onHTTPPassive: async ({ request, response, emitFinding }) => {
    // TODO: mine responses for opportunities worth raiding
    return;
  },
  onHTTPActive: async ({ request, response, emitFinding }) => {
    // TODO: execute active probes and record outcomes
    return;
  }
});
