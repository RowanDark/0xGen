import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tsconfigPaths from 'vite-tsconfig-paths';
import { TanStackRouterVite } from '@tanstack/router-plugin/vite';

export default defineConfig(({ mode }) => ({
  plugins: [react(), tsconfigPaths(), TanStackRouterVite()],
  server: {
    strictPort: true,
    port: 5173,
    host: '0.0.0.0'
  },
  preview: {
    port: 4173,
    host: '0.0.0.0'
  },
  define: {
    __DEVTOOLS_ENABLED__: mode !== 'production'
  }
}));
