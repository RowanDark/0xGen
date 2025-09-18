// plugins/grapher/plugin.js
const { register } = require('../../sdk/plugin-sdk');

register({
  name: 'grapher',
  onStart: async ({ emitFinding, config }) => {
    // TODO: construct graph storage and indexing primitives
    return;
  },
  onHTTPPassive: async ({ request, response, emitFinding }) => {
    // TODO: capture relationships from passive telemetry
    return;
  },
  onHTTPActive: async ({ request, response, emitFinding }) => {
    // TODO: connect graph updates with active reconnaissance findings
    return;
  }
});
