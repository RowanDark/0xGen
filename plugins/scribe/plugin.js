// plugins/scribe/plugin.js
const { register } = require('../../sdk/plugin-sdk');

register({
  name: 'scribe',
  onStart: async ({ emitFinding, config }) => {
    // TODO: initialize reporting pipelines and load templates
    return;
  },
  onHTTPPassive: async ({ request, response, emitFinding }) => {
    // Scribe focuses on reporting; passive hooks are unused for now.
    return;
  },
  onHTTPActive: async ({ request, response, emitFinding }) => {
    // Reporting plugins generally do not issue active requests.
    return;
  }
});
