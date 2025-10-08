import React from 'react';
import ReactDOM from 'react-dom/client';
import { RouterProvider } from '@tanstack/react-router';

import './styles.css';
import { router } from './router';
import { AppErrorBoundary } from './providers/error-boundary';
import { Toaster } from './providers/toaster';

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Unable to find root element');
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <Toaster />
      <RouterProvider router={router} />
    </AppErrorBoundary>
  </React.StrictMode>
);
