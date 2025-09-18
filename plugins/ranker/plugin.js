// plugins/ranker/plugin.js
const { register } = require('../../sdk/plugin-sdk');

register({
  name: 'ranker',
  onStart: async ({ emitFinding, config }) => {
    // TODO: initialize prioritization models and load stored context
    return;
  },
  onHTTPPassive: async ({ request, response, emitFinding }) => {
    // TODO: observe passive data to refine prioritization scores
    return;
  },
  onHTTPActive: async ({ request, response, emitFinding }) => {
    // TODO: adjust rankings based on active testing outcomes
    return;
  }
});
