import { useId } from 'react';
import { Contrast, Palette } from 'lucide-react';

import { Button } from './ui/button';
import { ThemeName, ThemeScope, useTheme } from '../providers/theme-provider';

export function ThemeSwitcher() {
  const {
    theme,
    setTheme,
    themes,
    themeScope,
    setThemeScope,
    highContrast,
    toggleHighContrast,
    prefersReducedMotion,
    toggleReducedMotion,
    fontScale,
    setFontScale
  } = useTheme();
  const themeSelectId = useId();
  const scopeSelectId = useId();
  const fontScaleId = useId();
  const sliderValue = Math.round(fontScale * 100);
  const fontScaleDelta = sliderValue - 100;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <label htmlFor={themeSelectId} className="sr-only">
        Theme
      </label>
      <div className="relative">
        <Palette
          className="pointer-events-none absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <select
          id={themeSelectId}
          value={theme}
          onChange={(event) => setTheme(event.target.value as ThemeName)}
          className="h-9 appearance-none rounded-md border border-input bg-card pl-8 pr-8 text-sm font-medium text-foreground shadow-sm transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          {themes.map((option) => (
            <option key={option.value} value={option.value} className="bg-popover text-foreground">
              {option.label}
            </option>
          ))}
        </select>
      </div>
      <label htmlFor={scopeSelectId} className="sr-only">
        Theme scope
      </label>
      <select
        id={scopeSelectId}
        value={themeScope}
        onChange={(event) => setThemeScope(event.target.value as ThemeScope)}
        className="h-9 rounded-md border border-input bg-card px-3 text-sm font-medium text-foreground shadow-sm transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
      >
        <option value="project">This project</option>
        <option value="user">All projects</option>
      </select>
      <Button
        type="button"
        variant={highContrast ? 'default' : 'outline'}
        size="sm"
        aria-pressed={highContrast}
        onClick={toggleHighContrast}
        title={highContrast ? 'Disable high contrast' : 'Enable high contrast'}
        className="gap-2"
      >
        <Contrast className="h-4 w-4" aria-hidden />
        <span className="text-xs font-semibold">HC</span>
        <span className="sr-only">Toggle high contrast</span>
      </Button>
      <Button
        type="button"
        variant={prefersReducedMotion ? 'default' : 'outline'}
        size="sm"
        aria-pressed={prefersReducedMotion}
        onClick={toggleReducedMotion}
        title={prefersReducedMotion ? 'Disable reduced motion overrides' : 'Enable reduced motion'}
        className="gap-2"
      >
        <span className="text-xs font-semibold">RM</span>
        <span className="sr-only">Toggle reduced motion</span>
      </Button>
      <div className="flex items-center gap-2">
        <label htmlFor={fontScaleId} className="text-xs font-medium text-muted-foreground">
          Font scale
        </label>
        <input
          id={fontScaleId}
          type="range"
          min={100}
          max={130}
          step={5}
          value={sliderValue}
          onChange={(event) => setFontScale(Number(event.target.value) / 100)}
          className="h-2 w-24 cursor-pointer appearance-none rounded-full bg-muted"
          aria-valuemin={100}
          aria-valuemax={130}
          aria-valuenow={sliderValue}
          aria-valuetext={`Font size ${fontScaleDelta >= 0 ? '+' : ''}${fontScaleDelta}%`}
        />
        <span className="w-12 text-right text-xs font-semibold tabular-nums text-muted-foreground">
          {fontScaleDelta >= 0 ? '+' : ''}
          {fontScaleDelta}%
        </span>
      </div>
    </div>
  );

}
