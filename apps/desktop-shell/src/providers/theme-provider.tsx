import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState
} from 'react';

const THEME_STORAGE_PREFIX = 'glyph.theme';
const CONTRAST_STORAGE_PREFIX = 'glyph.high-contrast';

const THEME_OPTIONS = [
  { value: 'light', label: 'Light', tone: 'light' },
  { value: 'dark', label: 'Dark', tone: 'dark' },
  { value: 'cyber', label: 'Cyber', tone: 'dark' },
  { value: 'red-team', label: 'Red Team', tone: 'dark' },
  { value: 'blue-team', label: 'Blue Team', tone: 'dark' },
  { value: 'purple-team', label: 'Purple Team', tone: 'dark' },
  { value: 'amber', label: 'Blue-light friendly', tone: 'dark' },
  { value: 'cb-safe', label: 'Colorblind safe', tone: 'dark' }
] as const;

type ThemeOption = (typeof THEME_OPTIONS)[number];
export type ThemeName = ThemeOption['value'];

type ThemeContextValue = {
  theme: ThemeName;
  setTheme: (theme: ThemeName) => void;
  themes: readonly ThemeOption[];
  highContrast: boolean;
  setHighContrast: (value: boolean) => void;
  toggleHighContrast: () => void;
  prefersReducedMotion: boolean;
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

function themeStorageKey(projectId: string) {
  return `${THEME_STORAGE_PREFIX}.${projectId}`;
}

function contrastStorageKey(projectId: string) {
  return `${CONTRAST_STORAGE_PREFIX}.${projectId}`;
}

function isThemeName(value: unknown): value is ThemeName {
  if (typeof value !== 'string') {
    return false;
  }
  return THEME_OPTIONS.some((option) => option.value === value);
}

function readStoredTheme(storage: Storage | null, projectId: string): ThemeName | null {
  if (!storage) {
    return null;
  }
  const stored = storage.getItem(themeStorageKey(projectId));
  return isThemeName(stored) ? stored : null;
}

function readStoredHighContrast(storage: Storage | null, projectId: string): boolean {
  if (!storage) {
    return false;
  }
  return storage.getItem(contrastStorageKey(projectId)) === '1';
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
  root: HTMLElement | null = getDocumentRoot()
) {
  if (!root) {
    return;
  }
  root.setAttribute('data-theme', theme);
  root.setAttribute('data-contrast', highContrast ? 'high' : 'normal');
  root.setAttribute('data-motion', prefersReducedMotion ? 'reduce' : 'default');
  root.style.colorScheme = DARK_THEMES.has(theme) ? 'dark' : 'light';
}

export function bootstrapTheme() {
  const root = getDocumentRoot();
  const projectId = getProjectId(root);
  const storage = getStorage();
  const storedTheme = readStoredTheme(storage, projectId);
  const systemTheme = getSystemTheme();
  const initialTheme = storedTheme ?? systemTheme;
  const highContrast = readStoredHighContrast(storage, projectId);
  const prefersReducedMotion = getSystemReducedMotion();

  applyDocumentTheme(initialTheme, highContrast, prefersReducedMotion, root);
}

type ThemeProviderProps = {
  children: React.ReactNode;
  projectId?: string;
};

export function ThemeProvider({ children, projectId: projectIdProp }: ThemeProviderProps) {
  const root = getDocumentRoot();
  const projectId = useMemo(() => projectIdProp ?? getProjectId(root), [projectIdProp, root]);
  const storage = useMemo(() => getStorage(), []);
  const storedTheme = useMemo(() => readStoredTheme(storage, projectId), [storage, projectId]);
  const storedHighContrast = useMemo(
    () => readStoredHighContrast(storage, projectId),
    [storage, projectId]
  );

  const [theme, setThemeState] = useState<ThemeName>(storedTheme ?? getSystemTheme());
  const [userHasLockedTheme, setUserHasLockedTheme] = useState(() => Boolean(storedTheme));
  const [highContrast, setHighContrastState] = useState<boolean>(storedHighContrast);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState<boolean>(
    getSystemReducedMotion()
  );

  useEffect(() => {
    applyDocumentTheme(theme, highContrast, prefersReducedMotion, root);
  }, [theme, highContrast, prefersReducedMotion, root]);

  useEffect(() => {
    if (!storage) {
      return;
    }
    storage.setItem(contrastStorageKey(projectId), highContrast ? '1' : '0');
  }, [highContrast, storage, projectId]);

  useEffect(() => {
    if (!storage) {
      return;
    }
    if (userHasLockedTheme) {
      storage.setItem(themeStorageKey(projectId), theme);
    }
  }, [theme, storage, projectId, userHasLockedTheme]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    const media = window.matchMedia(MEDIA_QUERY_REDUCED_MOTION);
    const update = (event: MediaQueryListEvent | MediaQueryList) => {
      setPrefersReducedMotion(event.matches);
    };

    update(media);

    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', update);
      return () => media.removeEventListener('change', update);
    }
    media.addListener(update);
    return () => media.removeListener(update);
  }, []);

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

  const handleSetHighContrast = useCallback((value: boolean) => {
    setHighContrastState(value);
  }, []);

  const toggleHighContrast = useCallback(() => {
    setHighContrastState((current) => !current);
  }, []);

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme,
      setTheme: handleSetTheme,
      themes: THEME_OPTIONS,
      highContrast,
      setHighContrast: handleSetHighContrast,
      toggleHighContrast,
      prefersReducedMotion,
      isDark: DARK_THEMES.has(theme),
      projectId
    }),
    [
      theme,
      handleSetTheme,
      highContrast,
      handleSetHighContrast,
      toggleHighContrast,
      prefersReducedMotion,
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
