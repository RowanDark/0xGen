# Glyph Desktop Shell

Cross-platform Tauri shell for the Glyph platform. The application is built with React, Vite, Tailwind CSS, and shadcn/ui components. Routing is powered by TanStack Router with a file-based route tree.

## Development

```bash
pnpm install
pnpm tauri:dev
pnpm dev
```

The shell proxies all renderer requests through the Tauri command layer. The base URL for the local Glyph API can be configured with `GLYPH_API_URL` (defaults to `http://127.0.0.1:8713`). Only loopback origins are accepted.

To enable the router devtools in development builds set `GLYPH_ENABLE_DEVTOOLS=1` before launching the app. The production build ships with devtools disabled by default.

## Testing

The accessibility regression suite depends on the Playwright browser binaries. Install them before running the checks:

```bash
pnpm --dir apps/desktop-shell exec playwright install --with-deps
pnpm --dir apps/desktop-shell test:a11y
```

## Security

- Content Security Policy locks all requests to the local application bundle and the configured Glyph API origin.
- Node integration is not available and no privileged APIs are exposed to the renderer. File system access is disabled.
- The Tauri backend exposes a narrow IPC surface: list runs, start a run, and stream run events via server-sent events. Event streams are proxied over a secure channel and can be revoked on demand.
- Devtools only open when explicitly enabled via `GLYPH_ENABLE_DEVTOOLS`.
