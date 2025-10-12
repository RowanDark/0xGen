import React from 'react';
import ReactDOM from 'react-dom/client';
import { RouterProvider } from '@tanstack/react-router';

import './styles.css';
import { router } from './router';
import { AppErrorBoundary } from './providers/error-boundary';
import { Toaster } from './providers/toaster';
import { ThemeProvider, bootstrapTheme } from './providers/theme-provider';
import { ArtifactProvider } from './providers/artifact-provider';
import { CommandCenterProvider } from './providers/command-center';
import { MetricsProvider } from './providers/metrics-provider';
import { CrashReporterProvider } from './providers/crash-reporter';

bootstrapTheme();

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Unable to find root element');
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <ThemeProvider>
      <CrashReporterProvider>
        <AppErrorBoundary>
          <ArtifactProvider>
            <MetricsProvider>
              <CommandCenterProvider>
                <Toaster />
                <RouterProvider router={router} />
              </CommandCenterProvider>
            </MetricsProvider>
          </ArtifactProvider>
        </AppErrorBoundary>
      </CrashReporterProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
