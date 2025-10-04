const { defineConfig } = require('@playwright/test');
const path = require('path');

const defaultBaseURL = 'http://127.0.0.1:4173';
const baseURL = process.env.DOCS_BASE_URL || defaultBaseURL;
const siteDir = path.resolve(__dirname, '.site');

module.exports = defineConfig({
  testDir: path.resolve(__dirname, 'tests'),
  timeout: 120 * 1000,
  expect: {
    toHaveScreenshot: {
      maxDiffPixelRatio: 0.01,
    },
  },
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL,
    viewport: { width: 1280, height: 720 },
    colorScheme: 'light',
    deviceScaleFactor: 1,
  },
  globalSetup: require.resolve('./scripts/global-setup'),
  webServer: process.env.DOCS_BASE_URL
    ? undefined
    : {
        command: `python3 -m http.server 4173 --directory "${siteDir}"`,
        url: defaultBaseURL,
        reuseExistingServer: !process.env.CI,
        timeout: 120 * 1000,
      },
});
