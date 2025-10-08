import { useId } from 'react';
import { Contrast, Palette } from 'lucide-react';

import { Button } from './ui/button';
import { ThemeName, useTheme } from '../providers/theme-provider';

export function ThemeSwitcher() {
  const {
    theme,
    setTheme,
    themes,
    highContrast,
    toggleHighContrast,
    prefersReducedMotion
  } = useTheme();
  const selectId = useId();

  return (
    <div className="flex items-center gap-2">
      <label htmlFor={selectId} className="sr-only">
        Theme
      </label>
      <div className="relative">
        <Palette
          className="pointer-events-none absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <select
          id={selectId}
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
      {prefersReducedMotion && (
        <span
          className="rounded-md border border-dashed border-border px-2 py-1 text-xs font-medium text-muted-foreground"
          role="status"
          aria-live="polite"
          title="System preference for reduced motion is active"
        >
          Reduced motion
        </span>
      )}
    </div>
  );
}
