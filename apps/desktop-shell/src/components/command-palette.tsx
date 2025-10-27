import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { createPortal } from 'react-dom';

import type { Command as CommandType } from '../providers/command-center';
import { useTheme } from '../providers/theme-provider';

type PaletteCommand = CommandType & { shortcuts: string[] };

type CommandPaletteProps = {
  isOpen: boolean;
  onClose: () => void;
  commands: PaletteCommand[];
  onRun: (command: PaletteCommand) => void;
};

function formatShortcut(shortcut: string) {
  return shortcut
    .split('+')
    .map((part) => {
      switch (part) {
        case 'meta':
          return '⌘';
        case 'ctrl':
          return 'Ctrl';
        case 'alt':
          return '⌥';
        case 'shift':
          return '⇧';
        case 'space':
          return 'Space';
        default:
          return part.length === 1 ? part.toUpperCase() : part.replace(/\b\w/g, (char) => char.toUpperCase());
      }
    })
    .join(' ');
}

const portalTarget = typeof document !== 'undefined' ? document.body : null;

export function CommandPalette({ isOpen, onClose, commands, onRun }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { prefersReducedMotion } = useTheme();

  useEffect(() => {
    if (!isOpen) {
      setQuery('');
      setActiveIndex(0);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) {
      return;
    }
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const timer = window.setTimeout(() => {
      inputRef.current?.focus();
    }, 0);
    return () => {
      window.clearTimeout(timer);
      document.body.style.overflow = previousOverflow;
    };
  }, [isOpen]);

  const grouped = useMemo(() => {
    if (!isOpen) {
      return [] as Array<[string, PaletteCommand[]]>;
    }
    const term = query.trim().toLowerCase();
    const list = commands
      .filter((command) => {
        if (!term) {
          return true;
        }
        const haystack = [command.title, command.description ?? '', ...(command.keywords ?? [])]
          .join(' ')
          .toLowerCase();
        return haystack.includes(term);
      })
      .sort((a, b) => (a.group ?? '').localeCompare(b.group ?? '') || a.title.localeCompare(b.title));

    const groups = new Map<string, PaletteCommand[]>();
    for (const command of list) {
      const key = command.group ?? 'Commands';
      const bucket = groups.get(key) ?? [];
      bucket.push(command);
      groups.set(key, bucket);
    }
    return Array.from(groups.entries());
  }, [commands, isOpen, query]);

  useEffect(() => {
    const total = grouped.reduce((sum, [, items]) => sum + items.length, 0);
    if (total === 0) {
      setActiveIndex(0);
      return;
    }
    setActiveIndex((previous) => Math.min(previous, total - 1));
  }, [grouped]);

  const flattened = useMemo(() => (isOpen ? grouped.flatMap(([, items]) => items) : []), [grouped, isOpen]);

  if (!portalTarget) {
    return null;
  }

  const handleKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActiveIndex((previous) => Math.min(previous + 1, Math.max(flattened.length - 1, 0)));
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActiveIndex((previous) => Math.max(previous - 1, 0));
    } else if (event.key === 'Enter') {
      event.preventDefault();
      const command = flattened[activeIndex];
      if (command) {
        onRun(command);
      }
    } else if (event.key === 'Escape') {
      event.preventDefault();
      onClose();
    }
  };

  const renderList = () => {
    if (flattened.length === 0) {
      return (
        <div className="px-4 py-6 text-sm text-muted-foreground" role="status">
          No commands found.
        </div>
      );
    }
    let index = -1;
    return grouped.map(([group, items]) => (
      <Fragment key={group}>
        <div className="px-4 py-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground" role="presentation">
          {group}
        </div>
        <ul role="listbox" aria-label={group} className="max-h-80 overflow-y-auto">
          {items.map((command) => {
            index += 1;
            const isActive = index === activeIndex;
            return (
              <li key={command.id}>
                <button
                  type="button"
                  role="option"
                  aria-selected={isActive}
                  onClick={() => onRun(command)}
                  disabled={command.disabled}
                  className={`flex w-full items-center justify-between gap-4 px-4 py-3 text-left text-sm transition focus:outline-none ${
                    isActive ? 'bg-primary/10 text-primary' : 'text-foreground hover:bg-muted'
                  } ${command.disabled ? 'cursor-not-allowed opacity-60' : ''}`}
                >
                  <div>
                    <p className="font-medium">{command.title}</p>
                    {command.description ? (
                      <p className="text-xs text-muted-foreground">{command.description}</p>
                    ) : null}
                  </div>
                  {command.shortcuts.length > 0 ? (
                    <div className="flex items-center gap-1 text-xs text-muted-foreground">
                      {command.shortcuts.map((shortcut) => (
                        <kbd
                          key={shortcut}
                          className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[0.65rem] uppercase"
                        >
                          {formatShortcut(shortcut)}
                        </kbd>
                      ))}
                    </div>
                  ) : null}
                </button>
              </li>
            );
          })}
        </ul>
      </Fragment>
    ));
  };

  const duration = prefersReducedMotion ? 0 : 0.18;

  return createPortal(
    <AnimatePresence>
      {isOpen ? (
        <motion.div
          ref={containerRef}
          className="fixed inset-0 z-50 flex items-start justify-center bg-background/70 p-4 backdrop-blur-sm"
          onMouseDown={(event) => {
            if (event.target === containerRef.current) {
              onClose();
            }
          }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration, ease: prefersReducedMotion ? 'linear' : [0.16, 1, 0.3, 1] }}
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-labelledby="command-palette-title"
            className="w-full max-w-xl overflow-hidden rounded-xl border border-border bg-card shadow-xl"
            initial={{ y: prefersReducedMotion ? 0 : -16, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: prefersReducedMotion ? 0 : -16, opacity: 0 }}
            transition={{ duration, ease: prefersReducedMotion ? 'linear' : [0.16, 1, 0.3, 1] }}
          >
            <div className="border-b border-border bg-muted/40 px-4 py-3">
              <label htmlFor="command-palette-search" className="sr-only">
                Search commands
              </label>
              <input
                id="command-palette-search"
                ref={inputRef}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Search actions, pages, or shortcuts"
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
                aria-describedby="command-palette-help"
              />
              <p id="command-palette-help" className="mt-2 text-xs text-muted-foreground">
                Navigate with ↑ ↓, press Enter to run a command, or Esc to close.
              </p>
            </div>
            <div className="max-h-96 overflow-y-auto" role="presentation">
              {renderList()}
            </div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>,
    portalTarget
  );
}

