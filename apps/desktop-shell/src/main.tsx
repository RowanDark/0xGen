import React from 'react';
import ReactDOM from 'react-dom/client';
import { RouterProvider } from '@tanstack/react-router';

import './styles.css';
import { router } from './router';
import { AppErrorBoundary } from './providers/error-boundary';
import { Toaster } from './providers/toaster';
import { ThemeProvider, bootstrapTheme } from './providers/theme-provider';

bootstrapTheme();

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Unable to find root element');
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <ThemeProvider>
      <AppErrorBoundary>
        <Toaster />
        <RouterProvider router={router} />
      </AppErrorBoundary>
    </ThemeProvider>
  </React.StrictMode>
);
