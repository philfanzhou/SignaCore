# SignaCore Admin Console

Vue 3, TypeScript, Vite, and Element Plus power the administrative UI embedded in the SignaCore host.

## Commands

```bash
npm ci
npm run dev
npm run test:coverage
npm run build
npm run preview
```

The package name is `signacore-admin`. At runtime the host replaces `__APP_TITLE__` and exposes `window.__APP_TITLE__`; the UI falls back to `SignaCore`. API calls use the same-origin `/api/admin` routes in production.

See [the frontend specification](docs/frontend-spec.md).
