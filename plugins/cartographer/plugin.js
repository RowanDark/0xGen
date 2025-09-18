// plugins/cartographer/plugin.js
const { register } = require('../../sdk/plugin-sdk');

register({
  name: 'cartographer',
  onStart: async ({ emitFinding, config }) => {
    // TODO: kick off surface mapping workflows
    return;
  },
  onHTTPPassive: async ({ request, response, emitFinding }) => {
    // TODO: evaluate discovered endpoints from passive data
    return;
  },
  onHTTPActive: async ({ request, response, emitFinding }) => {
    // TODO: drive follow-up requests for discovered surfaces
    return;
  }
});
