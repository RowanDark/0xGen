// plugins/excavator/crawl.js
const { chromium } = require('playwright');

(async () => {
  const url = process.env.TARGET_URL || process.argv[2] || 'https://example.com';
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  try {
    await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
    const links = await page.$$eval('a[href]', (els) => els.map((e) => e.href));
    const scripts = await page.$$eval('script', (els) =>
      els.map((s) => ({
        src: s.src || null,
        content: s.innerText ? s.innerText.slice(0, 200) : null
      }))
    );
    const result = {
      target: url,
      links: Array.from(new Set(links)).slice(0, 200),
      scripts: scripts.slice(0, 50)
    };
    console.log(JSON.stringify(result, null, 2));
    await browser.close();
    process.exit(0);
  } catch (e) {
    console.error('crawl error:', e);
    try {
      await browser.close();
    } catch (_) {}
    process.exit(2);
  }
})();
