import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

type RouteTarget = {
  name: string;
  path: string;
  readySelector: string;
};

const ROUTES: RouteTarget[] = [
  {
    name: 'Operations overview',
    path: '/',
    readySelector: 'h1:has-text("Operations overview")'
  },
  {
    name: 'Runs',
    path: '/runs',
    readySelector: 'h1:has-text("Runs")'
  },
  {
    name: 'Flows',
    path: '/flows',
    readySelector: 'h1:has-text("Flow timeline")'
  },
  {
    name: 'Cases',
    path: '/cases',
    readySelector: 'main'
  }
];

const SERIOUS_IMPACTS = new Set(['serious', 'critical']);

const THEMES = ['light', 'dark', 'cyber', 'red', 'blue', 'purple', 'amber', 'cb-safe'] as const;

const STORAGE_KEYS = {
  projectTheme: '0xgen.theme.project.default',
  themeScope: '0xgen.theme.scope.default',
  userTheme: '0xgen.theme.user',
  legacyTheme: '0xgen.theme.default',
  highContrast: '0xgen.high-contrast.default',
  motion: '0xgen.motion.default',
  fontScale: '0xgen.font-scale'
} as const;

test.describe('Accessibility regressions', () => {
  for (const themeName of THEMES) {
    test.describe(`${themeName} theme`, () => {
      for (const route of ROUTES) {
        test(`should not introduce critical issues on ${route.name}`, async ({ page }, testInfo) => {
          await page.addInitScript(({ theme, keys }) => {
            try {
              window.localStorage.clear();
              window.localStorage.setItem(keys.projectTheme, theme);
              window.localStorage.setItem(keys.themeScope, 'project');
              window.localStorage.removeItem(keys.userTheme);
              window.localStorage.removeItem(keys.legacyTheme);
              window.localStorage.setItem(keys.highContrast, '0');
              window.localStorage.setItem(keys.motion, '0');
              window.localStorage.setItem(keys.fontScale, '1.00');
            } catch (error) {
              // Ignore storage failures in headless environments.
            }
          }, { theme: themeName, keys: STORAGE_KEYS });

          await page.goto(route.path, { waitUntil: 'domcontentloaded' });
          await page.waitForSelector(route.readySelector, { state: 'visible' });

          const analysis = await new AxeBuilder({ page })
            .include('main')
            .analyze();

          const seriousViolations = analysis.violations.filter((violation) =>
            SERIOUS_IMPACTS.has(violation.impact ?? '')
          );

          const summary = analysis.violations
            .map((violation) => `${violation.impact ?? 'unknown'}: ${violation.id} → ${violation.help}`)
            .join('\n');

          await testInfo.attach('axe-report', {
            body: Buffer.from(JSON.stringify(analysis, null, 2)),
            contentType: 'application/json'
          });

          if (summary) {
            await testInfo.attach('axe-summary.txt', {
              body: Buffer.from(summary),
              contentType: 'text/plain'
            });
          }

          const contrastRatios = await page.evaluate(() => {
            const styles = getComputedStyle(document.documentElement);

            function parseHsl(value: string) {
              const [h, s, l] = value
                .trim()
                .split(/\s+/)
                .map((part, index) =>
                  index === 0 ? Number.parseFloat(part) : Number.parseFloat(part.replace('%', '')) / 100
                );
              if ([h, s, l].some((component) => Number.isNaN(component))) {
                return null;
              }
              return { h, s, l };
            }

            function hslToRgb(h: number, s: number, l: number) {
              const normalizedHue = ((h % 360) + 360) % 360;
              const c = (1 - Math.abs(2 * l - 1)) * s;
              const x = c * (1 - Math.abs(((normalizedHue / 60) % 2) - 1));
              const m = l - c / 2;

              let r = 0;
              let g = 0;
              let b = 0;

              if (normalizedHue < 60) {
                r = c;
                g = x;
              } else if (normalizedHue < 120) {
                r = x;
                g = c;
              } else if (normalizedHue < 180) {
                g = c;
                b = x;
              } else if (normalizedHue < 240) {
                g = x;
                b = c;
              } else if (normalizedHue < 300) {
                r = x;
                b = c;
              } else {
                r = c;
                b = x;
              }

              return [r + m, g + m, b + m];
            }

            function channelToLuminance(channel: number) {
              return channel <= 0.03928 ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4);
            }

            function relativeLuminance(rgb: number[]) {
              const [r, g, b] = rgb.map(channelToLuminance);
              return 0.2126 * r + 0.7152 * g + 0.0722 * b;
            }

            function contrastRatio(l1: number, l2: number) {
              const [lighter, darker] = l1 >= l2 ? [l1, l2] : [l2, l1];
              return (lighter + 0.05) / (darker + 0.05);
            }

            const PAIRS: Array<[string, string]> = [
              ['--primary', '--primary-foreground'],
              ['--background', '--foreground']
            ];

            return PAIRS.reduce<Record<string, number>>((acc, [backgroundVar, foregroundVar]) => {
              const background = parseHsl(styles.getPropertyValue(backgroundVar));
              const foreground = parseHsl(styles.getPropertyValue(foregroundVar));
              if (!background || !foreground) {
                acc[`${foregroundVar} on ${backgroundVar}`] = Number.NaN;
                return acc;
              }

              const backgroundLuminance = relativeLuminance(
                hslToRgb(background.h, background.s, background.l)
              );
              const foregroundLuminance = relativeLuminance(
                hslToRgb(foreground.h, foreground.s, foreground.l)
              );

              acc[`${foregroundVar} on ${backgroundVar}`] = contrastRatio(
                backgroundLuminance,
                foregroundLuminance
              );
              return acc;
            }, {});
          });

          for (const [pair, ratio] of Object.entries(contrastRatios)) {
            expect.soft(Number.isFinite(ratio), `Contrast ratio for ${pair} is invalid`).toBe(true);
            expect(ratio ?? 0, `Contrast ratio for ${pair} below WCAG AA`).toBeGreaterThanOrEqual(4.5);
          }

          expect.soft(analysis.violations.length, 'Accessibility violations detected').toBe(0);
          expect(seriousViolations, 'Critical accessibility regressions detected').toEqual([]);
        });
      }
    });
  }
});
