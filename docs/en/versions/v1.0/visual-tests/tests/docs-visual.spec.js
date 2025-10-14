const { test, expect } = require('@playwright/test');
const fs = require('fs/promises');
const path = require('path');

const pages = [
  { slug: '/', name: 'home' },
  { slug: '/quickstart/', name: 'quickstart' },
  { slug: '/cli/', name: 'cli' },
  { slug: '/security/', name: 'security' },
];

const baselineBaseURL = process.env.DOCS_BASELINE_URL || 'https://rowandark.github.io/0xgen/';

async function captureBaselineScreenshot(browser, pageConfig, snapshotPath) {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    deviceScaleFactor: 1,
    colorScheme: 'light',
  });
  try {
    const baselinePage = await context.newPage();
    const target = new URL(pageConfig.slug, baselineBaseURL).toString();
    await baselinePage.goto(target, { waitUntil: 'networkidle' });
    await baselinePage.waitForTimeout(500);
    const buffer = await baselinePage.screenshot({ fullPage: true });
    await fs.mkdir(path.dirname(snapshotPath), { recursive: true });
    await fs.writeFile(snapshotPath, buffer);
  } finally {
    await context.close();
  }
}

test.describe('Docs visual regressions', () => {
  for (const pageConfig of pages) {
    test(`matches production baseline for ${pageConfig.name}`, async ({ page, browser }, testInfo) => {
      const snapshotPath = testInfo.snapshotPath(`${pageConfig.name}.png`);
      await captureBaselineScreenshot(browser, pageConfig, snapshotPath);

      await page.goto(pageConfig.slug, { waitUntil: 'networkidle' });
      await page.waitForTimeout(500);
      await expect(page).toHaveScreenshot(`${pageConfig.name}.png`, {
        fullPage: true,
      });
    });
  }
});
