import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState
} from 'react';

const THEME_STORAGE_PREFIX = 'glyph.theme';
const THEME_SCOPE_STORAGE_PREFIX = `${THEME_STORAGE_PREFIX}.scope`;
const PROJECT_THEME_STORAGE_PREFIX = `${THEME_STORAGE_PREFIX}.project`;
const USER_THEME_STORAGE_KEY = `${THEME_STORAGE_PREFIX}.user`;
const CONTRAST_STORAGE_PREFIX = 'glyph.high-contrast';
const MOTION_STORAGE_PREFIX = 'glyph.motion';
const FONT_SCALE_STORAGE_KEY = 'glyph.font-scale';

const THEME_OPTIONS = [
  { value: 'light', label: 'Light', tone: 'light' },
  { value: 'dark', label: 'Dark', tone: 'dark' },
  { value: 'cyber', label: 'Cyber', tone: 'dark' },
  { value: 'red', label: 'Red', tone: 'dark' },
  { value: 'blue', label: 'Blue', tone: 'dark' },
  { value: 'purple', label: 'Purple', tone: 'dark' },
  { value: 'amber', label: 'Amber', tone: 'dark' },
  { value: 'cb-safe', label: 'Colorblind safe', tone: 'dark' }
] as const;

type ThemeOption = (typeof THEME_OPTIONS)[number];
export type ThemeName = ThemeOption['value'];
export type ThemeScope = 'user' | 'project';

type ThemeContextValue = {
  theme: ThemeName;
  setTheme: (theme: ThemeName) => void;
  themes: readonly ThemeOption[];
  themeScope: ThemeScope;
  setThemeScope: (scope: ThemeScope) => void;
  highContrast: boolean;
  setHighContrast: (value: boolean) => void;
  toggleHighContrast: () => void;
  prefersReducedMotion: boolean;
  setPrefersReducedMotion: (value: boolean) => void;
  toggleReducedMotion: () => void;
  fontScale: number;
  setFontScale: (scale: number) => void;
  isDark: boolean;
  projectId: string;
};

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

const DEFAULT_THEME: ThemeName = 'light';
const DARK_THEMES = new Set<ThemeName>(
  THEME_OPTIONS.filter((option) => option.tone === 'dark').map((option) => option.value)
);

const MEDIA_QUERY_DARK = '(prefers-color-scheme: dark)';
const MEDIA_QUERY_REDUCED_MOTION = '(prefers-reduced-motion: reduce)';

function getDocumentRoot(): HTMLElement | null {
  if (typeof document === 'undefined') {
    return null;
  }
  return document.documentElement;
}

function getProjectId(root: HTMLElement | null = getDocumentRoot()): string {
  return root?.dataset.project ?? 'default';
}

function getStorage(): Storage | null {
  if (typeof window === 'undefined') {
    return null;
  }
  try {
    return window.localStorage;
  } catch (error) {
    return null;
  }
}

function legacyThemeStorageKey(projectId: string) {
  return `${THEME_STORAGE_PREFIX}.${projectId}`;
}

function projectThemeStorageKey(projectId: string) {
  return `${PROJECT_THEME_STORAGE_PREFIX}.${projectId}`;
}

function themeScopeStorageKey(projectId: string) {
  return `${THEME_SCOPE_STORAGE_PREFIX}.${projectId}`;
}

function contrastStorageKey(projectId: string) {
  return `${CONTRAST_STORAGE_PREFIX}.${projectId}`;
}

function motionStorageKey(projectId: string) {
  return `${MOTION_STORAGE_PREFIX}.${projectId}`;
}

function isThemeName(value: unknown): value is ThemeName {
  if (typeof value !== 'string') {
    return false;
  }
  return THEME_OPTIONS.some((option) => option.value === value);
}

function isThemeScope(value: unknown): value is ThemeScope {
  return value === 'user' || value === 'project';
}

function parseTheme(value: string | null): ThemeName | null {
  return isThemeName(value) ? value : null;
}

type StoredThemePreferences = {
  theme: ThemeName | null;
  scope: ThemeScope;
  userTheme: ThemeName | null;
  projectTheme: ThemeName | null;
  legacyTheme: ThemeName | null;
};

function resolveStoredThemePreferences(storage: Storage | null, projectId: string): StoredThemePreferences {
  const userTheme = storage ? parseTheme(storage.getItem(USER_THEME_STORAGE_KEY)) : null;
  const projectTheme = storage ? parseTheme(storage.getItem(projectThemeStorageKey(projectId))) : null;
  const legacyTheme = storage ? parseTheme(storage.getItem(legacyThemeStorageKey(projectId))) : null;
  const storedScopeValue = storage ? storage.getItem(themeScopeStorageKey(projectId)) : null;
  const storedScope = isThemeScope(storedScopeValue) ? storedScopeValue : null;

  let scope: ThemeScope = storedScope ?? 'project';
  let theme: ThemeName | null = null;

  if (storedScope === 'project') {
    theme = projectTheme ?? legacyTheme ?? null;
  } else if (storedScope === 'user') {
    theme = userTheme ?? null;
    if (!theme && (projectTheme || legacyTheme)) {
      scope = 'project';
      theme = projectTheme ?? legacyTheme ?? null;
    }
  }

  if (!storedScope) {
    if (projectTheme) {
      scope = 'project';
      theme = projectTheme;
    } else if (legacyTheme) {
      scope = 'project';
      theme = legacyTheme;
    } else if (userTheme) {
      scope = 'user';
      theme = userTheme;
    }
  }

  return {
    theme,
    scope,
    userTheme,
    projectTheme,
    legacyTheme
  };
}

function readStoredHighContrast(storage: Storage | null, projectId: string): boolean {
  if (!storage) {
    return false;
  }
  return storage.getItem(contrastStorageKey(projectId)) === '1';
}

function readStoredReducedMotion(storage: Storage | null, projectId: string): boolean | null {
  if (!storage) {
    return null;
  }
  const stored = storage.getItem(motionStorageKey(projectId));
  if (stored === '1') {
    return true;
  }
  if (stored === '0') {
    return false;
  }
  return null;
}

function readStoredFontScale(storage: Storage | null): number | null {
  if (!storage) {
    return null;
  }
  const stored = storage.getItem(FONT_SCALE_STORAGE_KEY);
  if (!stored) {
    return null;
  }
  const value = Number.parseFloat(stored);
  if (!Number.isFinite(value)) {
    return null;
  }
  if (value < 1 || value > 1.3) {
    return null;
  }
  return value;
}

function getSystemTheme(): ThemeName {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return DEFAULT_THEME;
  }
  return window.matchMedia(MEDIA_QUERY_DARK).matches ? 'dark' : DEFAULT_THEME;
}

function getSystemReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false;
  }
  return window.matchMedia(MEDIA_QUERY_REDUCED_MOTION).matches;
}

function applyDocumentTheme(
  theme: ThemeName,
  highContrast: boolean,
  prefersReducedMotion: boolean,
  fontScale: number,
  root: HTMLElement | null = getDocumentRoot()
) {
  if (!root) {
    return;
  }
  root.setAttribute('data-theme', theme);
  root.setAttribute('data-contrast', highContrast ? 'high' : 'normal');
  root.setAttribute('data-motion', prefersReducedMotion ? 'reduce' : 'default');
  root.setAttribute('data-font-scale', fontScale.toFixed(2));
  root.style.colorScheme = DARK_THEMES.has(theme) ? 'dark' : 'light';
  root.style.setProperty('--font-scale', fontScale.toFixed(2));
}

export function bootstrapTheme() {
  const root = getDocumentRoot();
  const projectId = getProjectId(root);
  const storage = getStorage();
  const storedPreferences = resolveStoredThemePreferences(storage, projectId);
  const systemTheme = getSystemTheme();
  const initialTheme = storedPreferences.theme ?? systemTheme;
  const highContrast = readStoredHighContrast(storage, projectId);
  const storedReducedMotion = readStoredReducedMotion(storage, projectId);
  const prefersReducedMotion = storedReducedMotion ?? getSystemReducedMotion();
  const fontScale = readStoredFontScale(storage) ?? 1;

  applyDocumentTheme(initialTheme, highContrast, prefersReducedMotion, fontScale, root);
}

type ThemeProviderProps = {
  children: React.ReactNode;
  projectId?: string;
};

export function ThemeProvider({ children, projectId: projectIdProp }: ThemeProviderProps) {
  const root = getDocumentRoot();
  const projectId = useMemo(() => projectIdProp ?? getProjectId(root), [projectIdProp, root]);
  const storage = useMemo(() => getStorage(), []);
  const storedPreferences = useMemo(
    () => resolveStoredThemePreferences(storage, projectId),
    [storage, projectId]
  );
  const storedHighContrast = useMemo(
    () => readStoredHighContrast(storage, projectId),
    [storage, projectId]
  );
  const storedReducedMotion = useMemo(
    () => readStoredReducedMotion(storage, projectId),
    [storage, projectId]
  );
  const storedFontScale = useMemo(() => readStoredFontScale(storage), [storage]);
  const { legacyTheme, projectTheme: storedProjectTheme, userTheme: storedUserTheme } =
    storedPreferences;

  const [theme, setThemeState] = useState<ThemeName>(
    storedPreferences.theme ?? getSystemTheme()
  );
  const [themeScope, setThemeScopeState] = useState<ThemeScope>(storedPreferences.scope);
  const [userHasLockedTheme, setUserHasLockedTheme] = useState(() =>
    Boolean(storedPreferences.theme ?? storedProjectTheme ?? storedUserTheme)
  );
  const [highContrast, setHighContrastState] = useState<boolean>(storedHighContrast);
  const [prefersReducedMotion, setPrefersReducedMotionState] = useState<boolean>(
    storedReducedMotion ?? getSystemReducedMotion()
  );
  const [userHasLockedMotion, setUserHasLockedMotion] = useState(
    () => storedReducedMotion !== null
  );
  const [fontScale, setFontScaleState] = useState<number>(storedFontScale ?? 1);

  useEffect(() => {
    if (!storage) {
      return;
    }
    if (legacyTheme && !storedProjectTheme) {
      try {
        storage.setItem(projectThemeStorageKey(projectId), legacyTheme);
        storage.removeItem(legacyThemeStorageKey(projectId));
      } catch (error) {
        // Swallow persistence errors to avoid crashing the shell when storage is unavailable.
      }
    }
  }, [legacyTheme, storedProjectTheme, storage, projectId]);

  useEffect(() => {
    applyDocumentTheme(theme, highContrast, prefersReducedMotion, fontScale, root);
  }, [theme, highContrast, prefersReducedMotion, fontScale, root]);

  useEffect(() => {
    if (!storage) {
      return;
    }
    try {
      storage.setItem(contrastStorageKey(projectId), highContrast ? '1' : '0');
    } catch (error) {
      // Swallow persistence errors to avoid crashing the shell when storage is unavailable.
    }
  }, [highContrast, storage, projectId]);

  useEffect(() => {
    if (!storage) {
      return;
    }
    try {
      storage.setItem(themeScopeStorageKey(projectId), themeScope);
    } catch (error) {
      // Swallow persistence errors to avoid crashing the shell when storage is unavailable.
    }
  }, [themeScope, storage, projectId]);

  useEffect(() => {
    if (!storage) {
      return;
    }
    if (!userHasLockedTheme) {
      return;
    }
    const key =
      themeScope === 'project'
        ? projectThemeStorageKey(projectId)
        : USER_THEME_STORAGE_KEY;
    try {
      storage.setItem(key, theme);
    } catch (error) {
      // Swallow persistence errors to avoid crashing the shell when storage is unavailable.
    }
  }, [theme, themeScope, storage, projectId, userHasLockedTheme]);

  useEffect(() => {
    if (!storage) {
      return;
    }
    if (!userHasLockedMotion) {
      try {
        storage.removeItem(motionStorageKey(projectId));
      } catch (error) {
        // Swallow persistence errors to avoid crashing the shell when storage is unavailable.
      }
      return;
    }
    try {
      storage.setItem(motionStorageKey(projectId), prefersReducedMotion ? '1' : '0');
    } catch (error) {
      // Swallow persistence errors to avoid crashing the shell when storage is unavailable.
    }
  }, [prefersReducedMotion, storage, projectId, userHasLockedMotion]);

  useEffect(() => {
    if (!storage) {
      return;
    }
    try {
      storage.setItem(FONT_SCALE_STORAGE_KEY, fontScale.toFixed(2));
    } catch (error) {
      // Swallow persistence errors to avoid crashing the shell when storage is unavailable.
    }
  }, [fontScale, storage]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    if (userHasLockedMotion) {
      return;
    }
    const media = window.matchMedia(MEDIA_QUERY_REDUCED_MOTION);
    const update = (event: MediaQueryListEvent | MediaQueryList) => {
      setPrefersReducedMotionState(event.matches);
    };

    update(media);

    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', update);
      return () => media.removeEventListener('change', update);
    }
    media.addListener(update);
    return () => media.removeListener(update);
  }, [userHasLockedMotion]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    if (userHasLockedTheme) {
      return;
    }

    const media = window.matchMedia(MEDIA_QUERY_DARK);
    const update = (event: MediaQueryListEvent | MediaQueryList) => {
      setThemeState(event.matches ? 'dark' : DEFAULT_THEME);
    };

    update(media);

    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', update);
      return () => media.removeEventListener('change', update);
    }
    media.addListener(update);
    return () => media.removeListener(update);
  }, [userHasLockedTheme]);

  const handleSetTheme = useCallback((nextTheme: ThemeName) => {
    setThemeState(nextTheme);
    setUserHasLockedTheme(true);
  }, []);

  const handleSetThemeScope = useCallback(
    (nextScope: ThemeScope) => {
      setThemeScopeState(nextScope);
      setUserHasLockedTheme(true);
      if (!storage) {
        return;
      }
      setThemeState((currentTheme) => {
        const storedThemeForScope =
          nextScope === 'project'
            ? parseTheme(storage.getItem(projectThemeStorageKey(projectId))) ??
              parseTheme(storage.getItem(legacyThemeStorageKey(projectId)))
            : parseTheme(storage.getItem(USER_THEME_STORAGE_KEY));
        return storedThemeForScope ?? currentTheme;
      });
    },
    [projectId, storage]
  );

  const handleSetHighContrast = useCallback((value: boolean) => {
    setHighContrastState(value);
  }, []);

  const toggleHighContrast = useCallback(() => {
    setHighContrastState((current) => !current);
  }, []);

  const handleSetPrefersReducedMotion = useCallback((value: boolean) => {
    setPrefersReducedMotionState(value);
    setUserHasLockedMotion(true);
  }, []);

  const toggleReducedMotion = useCallback(() => {
    setPrefersReducedMotionState((current) => {
      const next = !current;
      setUserHasLockedMotion(true);
      return next;
    });
  }, []);

  const handleSetFontScale = useCallback((scale: number) => {
    if (!Number.isFinite(scale)) {
      return;
    }
    setFontScaleState(Math.min(1.3, Math.max(1, scale)));
  }, []);

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme,
      setTheme: handleSetTheme,
      themes: THEME_OPTIONS,
      themeScope,
      setThemeScope: handleSetThemeScope,
      highContrast,
      setHighContrast: handleSetHighContrast,
      toggleHighContrast,
      prefersReducedMotion,
      setPrefersReducedMotion: handleSetPrefersReducedMotion,
      toggleReducedMotion,
      fontScale,
      setFontScale: handleSetFontScale,
      isDark: DARK_THEMES.has(theme),
      projectId
    }),
    [
      theme,
      handleSetTheme,
      themeScope,
      handleSetThemeScope,
      highContrast,
      handleSetHighContrast,
      toggleHighContrast,
      prefersReducedMotion,
      handleSetPrefersReducedMotion,
      toggleReducedMotion,
      fontScale,
      handleSetFontScale,
      projectId
    ]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
}

export const AVAILABLE_THEMES = THEME_OPTIONS;
