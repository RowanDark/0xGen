import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type PropsWithChildren
} from 'react';

import { CommandPalette } from '../components/command-palette';

type Shortcut = string | string[] | undefined;

export type Command = {
  id: string;
  title: string;
  description?: string;
  group?: string;
  keywords?: string[];
  shortcut?: Shortcut;
  run: () => void | Promise<void>;
  allowInInput?: boolean;
  disabled?: boolean;
  closeOnRun?: boolean;
};

type InternalCommand = Command & {
  shortcuts: string[];
};

type CommandCenterContextValue = {
  registerCommand: (command: Command) => () => void;
  openPalette: () => void;
  closePalette: () => void;
  togglePalette: () => void;
  isPaletteOpen: boolean;
};

const CommandCenterContext = createContext<CommandCenterContextValue | null>(null);

const isMac = typeof navigator !== 'undefined' ? /mac/i.test(navigator.platform) : false;

const modifierOrder = ['ctrl', 'meta', 'alt', 'shift'];

function normaliseKey(key: string) {
  if (key.length === 1) {
    return key.toLowerCase();
  }
  switch (key) {
    case ' ': {
      return 'space';
    }
    case 'ArrowUp':
    case 'ArrowDown':
    case 'ArrowLeft':
    case 'ArrowRight': {
      return key.replace('Arrow', '').toLowerCase();
    }
    default: {
      return key.toLowerCase();
    }
  }
}

function normaliseShortcut(shortcut: string): string[] {
  const parts = shortcut
    .split('+')
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean);
  if (parts.length === 0) {
    return [];
  }
  const key = normaliseKey(parts[parts.length - 1] ?? '');
  const modifiers = parts.slice(0, -1);

  const modifierVariants = modifiers.reduce<string[][]>((accumulator, modifier) => {
    if (modifier === 'mod') {
      const variants = [] as string[][];
      for (const existing of accumulator) {
        variants.push([...existing, 'meta']);
        variants.push([...existing, 'ctrl']);
      }
      return variants;
    }
    return accumulator.map((existing) => [...existing, modifier]);
  }, [[]]);

  const combos = modifierVariants.map((variant) => {
    const ordered = [...variant]
      .map((modifier) => (modifier === 'mod' ? (isMac ? 'meta' : 'ctrl') : modifier))
      .sort((a, b) => modifierOrder.indexOf(a) - modifierOrder.indexOf(b));
    return [...ordered, key].join('+');
  });

  return combos.length > 0 ? combos : [key];
}

function normaliseShortcutInput(shortcut: Shortcut): string[] {
  if (!shortcut) {
    return [];
  }
  if (Array.isArray(shortcut)) {
    return shortcut.flatMap((item) => normaliseShortcut(item));
  }
  return normaliseShortcut(shortcut);
}

function eventToShortcut(event: KeyboardEvent): string | null {
  if (event.key === 'Shift' || event.key === 'Control' || event.key === 'Alt' || event.key === 'Meta') {
    return null;
  }
  const modifiers: string[] = [];
  if (event.ctrlKey) modifiers.push('ctrl');
  if (event.metaKey) modifiers.push('meta');
  if (event.altKey) modifiers.push('alt');
  if (event.shiftKey) modifiers.push('shift');
  const key = normaliseKey(event.key);
  modifiers.sort((a, b) => modifierOrder.indexOf(a) - modifierOrder.indexOf(b));
  return [...modifiers, key].join('+');
}

function isTextInputElement(element: EventTarget | null): boolean {
  if (!(element instanceof HTMLElement)) {
    return false;
  }
  if (element.isContentEditable) {
    return true;
  }
  if (element.tagName === 'INPUT') {
    const type = (element as HTMLInputElement).type;
    return type !== 'checkbox' && type !== 'radio' && type !== 'button' && type !== 'submit' && type !== 'reset';
  }
  return element.tagName === 'TEXTAREA' || element.tagName === 'SELECT';
}

export function CommandCenterProvider({ children }: PropsWithChildren) {
  const [isPaletteOpen, setPaletteOpen] = useState(false);
  const [commands, setCommands] = useState<Map<string, InternalCommand>>(new Map());

  const commandsRef = useRef(commands);
  const shortcutMapRef = useRef<Map<string, string>>(new Map());

  useEffect(() => {
    commandsRef.current = commands;
    const map = new Map<string, string>();
    for (const [id, command] of commands.entries()) {
      for (const shortcut of command.shortcuts) {
        map.set(shortcut, id);
      }
    }
    shortcutMapRef.current = map;
  }, [commands]);

  const registerCommand = useCallback((command: Command) => {
    const shortcuts = normaliseShortcutInput(command.shortcut);
    setCommands((previous) => {
      const next = new Map(previous);
      next.set(command.id, { ...command, shortcuts });
      return next;
    });
    return () => {
      setCommands((previous) => {
        if (!previous.has(command.id)) {
          return previous;
        }
        const next = new Map(previous);
        next.delete(command.id);
        return next;
      });
    };
  }, []);

  const openPalette = useCallback(() => {
    setPaletteOpen(true);
  }, []);

  const closePalette = useCallback(() => {
    setPaletteOpen(false);
  }, []);

  const togglePalette = useCallback(() => {
    setPaletteOpen((previous) => !previous);
  }, []);

  const executeCommand = useCallback(
    (command: InternalCommand, { viaPalette }: { viaPalette: boolean }) => {
      if (command.disabled) {
        return;
      }
      try {
        const result = command.run();
        if (result && typeof (result as Promise<unknown>).then === 'function') {
          void (result as Promise<unknown>).catch((error) => {
            console.error('Command execution failed', error);
          });
        }
      } catch (error) {
        console.error('Command execution failed', error);
      }
      if (viaPalette && command.closeOnRun !== false) {
        closePalette();
      }
    },
    [closePalette]
  );

  useEffect(() => {
    const cleanup = registerCommand({
      id: 'command.palette',
      title: 'Show command palette',
      description: 'Search actions and navigation',
      group: 'Global',
      shortcut: 'mod+k',
      allowInInput: true,
      closeOnRun: false,
      run: () => {
        togglePalette();
      }
    });
    return cleanup;
  }, [registerCommand, togglePalette]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented) {
        return;
      }
      const combo = eventToShortcut(event);
      if (!combo) {
        return;
      }
      const commandId = shortcutMapRef.current.get(combo);
      if (!commandId) {
        return;
      }
      const command = commandsRef.current.get(commandId);
      if (!command) {
        return;
      }
      if (!command.allowInInput && isTextInputElement(event.target)) {
        return;
      }
      event.preventDefault();
      executeCommand(command, { viaPalette: false });
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [executeCommand]);

  const commandList = useMemo(() => Array.from(commands.values()), [commands]);

  return (
    <CommandCenterContext.Provider value={{ registerCommand, openPalette, closePalette, togglePalette, isPaletteOpen }}>
      {children}
      <CommandPalette
        isOpen={isPaletteOpen}
        onClose={closePalette}
        commands={commandList}
        onRun={(command) => executeCommand(command, { viaPalette: true })}
      />
    </CommandCenterContext.Provider>
  );
}

export function useCommandCenter() {
  const context = useContext(CommandCenterContext);
  if (!context) {
    throw new Error('useCommandCenter must be used within a CommandCenterProvider');
  }
  return context;
}

