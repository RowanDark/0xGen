import { Link, Outlet, createRootRoute, useNavigate, useRouterState } from '@tanstack/react-router';
import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { Menu, Play, RefreshCw, Archive, Command as CommandIcon } from 'lucide-react';
import { open } from '@tauri-apps/api/dialog';
import { toast } from 'sonner';

import { Button } from '../components/ui/button';
import { cn } from '../lib/utils';
import { ThemeSwitcher } from '../components/theme-switcher';
import { openArtifact } from '../lib/ipc';
import { useArtifact } from '../providers/artifact-provider';
import { useCommandCenter } from '../providers/command-center';

const Devtools = lazy(() => import('../screens/devtools'));

declare const __DEVTOOLS_ENABLED__: boolean;

const navigation = [
  { to: '/', label: 'Dashboard' },
  { to: '/flows', label: 'Flows' },
  { to: '/runs', label: 'Runs' },
  { to: '/cases', label: 'Cases' },
  { to: '/scope', label: 'Scope' }
];

function Header() {
  const { status, setStatusFromOpen } = useArtifact();
  const location = useRouterState({ select: (state) => state.location.pathname });
  const navigate = useNavigate();
  const { registerCommand, openPalette } = useCommandCenter();
  const offlineMode = Boolean(status?.loaded);
  const initialIndex = useMemo(() => {
    const exactMatch = navigation.findIndex((item) => location === item.to);
    if (exactMatch >= 0) {
      return exactMatch;
    }
    return navigation.findIndex((item) =>
      item.to === '/' ? location === item.to : location.startsWith(`${item.to}/`)
    );
  }, [location]);
  const [focusedIndex, setFocusedIndex] = useState(() => (initialIndex >= 0 ? initialIndex : 0));
  const linkRefs = useRef<(HTMLAnchorElement | null)[]>([]);

  useEffect(() => {
    if (initialIndex >= 0) {
      setFocusedIndex(initialIndex);
    }
  }, [initialIndex]);

  useEffect(() => {
    const cleanups = navigation.map((item) =>
      registerCommand({
        id: `nav.${item.to === '/' ? 'dashboard' : item.to.replace(/\//g, '-')}`,
        title: `Go to ${item.label}`,
        group: 'Navigation',
        keywords: ['go', 'navigate', item.label.toLowerCase()],
        run: () => navigate({ to: item.to })
      })
    );
    return () => {
      for (const cleanup of cleanups) {
        cleanup();
      }
    };
  }, [navigate, registerCommand]);

  const artifactSummary = useMemo(() => {
    if (!status?.manifest) {
      return offlineMode ? 'Replay artifact mounted' : 'Connected to daemon';
    }
    const createdAt = status.manifest.createdAt
      ? new Date(status.manifest.createdAt).toLocaleString()
      : undefined;
    const runner = status.manifest.runner?.glyphctlVersion ?? status.manifest.runner?.glyphdVersion;
    if (createdAt && runner) {
      return `Captured ${createdAt} • glyph ${runner}`;
    }
    if (createdAt) {
      return `Captured ${createdAt}`;
    }
    return 'Replay artifact mounted';
  }, [offlineMode, status?.manifest]);

  const handleOpenArtifact = async () => {
    try {
      const selection = await open({
        multiple: false,
        filters: [{ name: 'Glyph replay artifacts', extensions: ['tgz'] }]
      });
      const file = Array.isArray(selection) ? selection[0] : selection;
      if (!file || typeof file !== 'string') {
        return;
      }
      const summary = await openArtifact(file);
      setStatusFromOpen(summary);
      toast.success(
        `Mounted artifact with ${summary.caseCount} ${summary.caseCount === 1 ? 'case' : 'cases'}`
      );
    } catch (error) {
      console.error('Failed to open artifact', error);
      toast.error('Unable to open artifact');
    }
  };

  return (
    <header className="flex items-center justify-between border-b border-border bg-card px-4 py-3">
      <div className="flex items-center gap-2">
        <Menu className="h-5 w-5 text-muted-foreground" aria-hidden />
        <span className="font-semibold">Glyph Desktop</span>
      </div>
      <nav
        className="flex items-center gap-4 text-sm font-medium"
        role="menubar"
        aria-label="Primary navigation"
      >
        {navigation.map((item, index) => (
          <Link
            key={item.to}
            to={item.to}
            className={cn(
              'transition-colors hover:text-foreground/80',
              location === item.to ? 'text-foreground' : 'text-muted-foreground'
            )}
            tabIndex={focusedIndex === index ? 0 : -1}
            ref={(element) => {
              linkRefs.current[index] = element;
            }}
            role="menuitem"
            onFocus={() => setFocusedIndex(index)}
            onKeyDown={(event) => {
              if (event.key === 'ArrowRight') {
                event.preventDefault();
                const nextIndex = (index + 1) % navigation.length;
                setFocusedIndex(nextIndex);
                linkRefs.current[nextIndex]?.focus();
              } else if (event.key === 'ArrowLeft') {
                event.preventDefault();
                const previousIndex = (index - 1 + navigation.length) % navigation.length;
                setFocusedIndex(previousIndex);
                linkRefs.current[previousIndex]?.focus();
              } else if (event.key === 'Home') {
                event.preventDefault();
                setFocusedIndex(0);
                linkRefs.current[0]?.focus();
              } else if (event.key === 'End') {
                event.preventDefault();
                const lastIndex = navigation.length - 1;
                setFocusedIndex(lastIndex);
                linkRefs.current[lastIndex]?.focus();
              }
            }}
          >
            {item.label}
          </Link>
        ))}
      </nav>
      <div className="flex items-center gap-3">
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="hidden items-center gap-2 text-xs text-muted-foreground sm:inline-flex"
          onClick={openPalette}
        >
          <CommandIcon className="h-4 w-4" />
          Command menu
          <kbd className="ml-1 rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[0.65rem]">⌘K</kbd>
        </Button>
        <ThemeSwitcher />
        <div className="hidden flex-col text-xs text-muted-foreground sm:flex">
          <span className="font-medium text-foreground">{offlineMode ? 'Offline mode' : 'Live mode'}</span>
          <span className="truncate">{artifactSummary}</span>
        </div>
        <Button variant="outline" size="sm" className="gap-2" onClick={handleOpenArtifact}>
          <Archive className="h-4 w-4" />
          Open artifact
        </Button>
        <Button
          variant="secondary"
          size="sm"
          className="gap-2"
          disabled={offlineMode}
          title={offlineMode ? 'Unavailable while browsing a replay artifact' : undefined}
        >
          <Play className="h-4 w-4" />
          New run
        </Button>
      </div>
    </header>
  );
}

function RootComponent() {
  return (
    <div className="flex h-full flex-col">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      <Header />
      <main id="main-content" tabIndex={-1} className="flex-1 overflow-y-auto bg-background">
        <Suspense
          fallback={
            <div className="flex h-full items-center justify-center text-muted-foreground">
              <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
              Loading…
            </div>
          }
        >
          <Outlet />
        </Suspense>
      </main>
      {__DEVTOOLS_ENABLED__ && (
        <Suspense fallback={null}>
          <Devtools />
        </Suspense>
      )}
    </div>
  );
}

function RootErrorBoundary() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2">
      <h1 className="text-2xl font-semibold">Something went wrong</h1>
      <p className="text-muted-foreground">Please restart the application.</p>
    </div>
  );
}

export const Route = createRootRoute({
  component: RootComponent,
  errorComponent: RootErrorBoundary
});

export default RootComponent;
