import { useId } from 'react';

import { cn } from '../lib/utils';
import { useMode } from '../providers/mode-provider';

export function ModeSwitcher() {
  const { mode, setMode, options, config } = useMode();
  const labelId = useId();
  const descriptionId = useId();

  return (
    <div className="flex min-w-[14rem] flex-col gap-1 text-left">
      <span
        id={labelId}
        className="text-[0.65rem] font-semibold uppercase tracking-wide text-muted-foreground"
      >
        Team mode
      </span>
      <div
        role="radiogroup"
        aria-labelledby={labelId}
        aria-describedby={descriptionId}
        className="flex items-center gap-1 rounded-lg border border-border/60 bg-background/60 p-1 shadow-sm"
      >
        {options.map((option) => {
          const Icon = option.icon;
          const isActive = option.value === mode;
          return (
            <button
              key={option.value}
              type="button"
              role="radio"
              aria-checked={isActive}
              className={cn(
                'flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-semibold uppercase tracking-wide transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background',
                isActive
                  ? option.switcherActiveClass
                  : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground'
              )}
              onClick={() => setMode(option.value)}
            >
              <Icon
                aria-hidden
                className={cn('h-4 w-4', isActive ? option.switcherIconClass : 'text-muted-foreground')}
              />
              {option.shortLabel}
            </button>
          );
        })}
      </div>
      <p id={descriptionId} className="text-[0.7rem] text-muted-foreground">
        {config.description}
      </p>
    </div>
  );
}
