import { Link, Outlet, createRootRoute, useRouterState } from '@tanstack/react-router';
import { lazy, Suspense } from 'react';
import { Menu, Play, RefreshCw } from 'lucide-react';

import { Button } from '../components/ui/button';
import { cn } from '../lib/utils';
import { ThemeSwitcher } from '../components/theme-switcher';

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
  const location = useRouterState({ select: (state) => state.location.pathname });
  return (
    <header className="flex items-center justify-between border-b border-border bg-card px-4 py-3">
      <div className="flex items-center gap-2">
        <Menu className="h-5 w-5 text-muted-foreground" aria-hidden />
        <span className="font-semibold">Glyph Desktop</span>
      </div>
      <nav className="flex items-center gap-4 text-sm font-medium">
        {navigation.map((item) => (
          <Link
            key={item.to}
            to={item.to}
            className={cn(
              'transition-colors hover:text-foreground/80',
              location === item.to ? 'text-foreground' : 'text-muted-foreground'
            )}
          >
            {item.label}
          </Link>
        ))}
      </nav>
      <div className="flex items-center gap-3">
        <ThemeSwitcher />
        <Button variant="secondary" size="sm" className="gap-2">
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
      <Header />
      <main className="flex-1 overflow-y-auto bg-background">
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
