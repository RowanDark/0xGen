// plugins/seer/plugin.js
const { register } = require('../../sdk/plugin-sdk');

register({
  name: 'seer',
  onStart: async ({ emitFinding, config }) => {
    // TODO: configure detection heuristics and signal subscriptions
    return;
  },
  onHTTPPassive: async ({ request, response, emitFinding }) => {
    // TODO: analyze passive flows for suspicious behavior
    return;
  },
  onHTTPActive: async ({ request, response, emitFinding }) => {
    // TODO: trigger active confirmation checks when necessary
    return;
  }
});
