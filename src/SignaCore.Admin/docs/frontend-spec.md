# SignaCore Admin Console Specification

## Purpose

The console provides administrative session management, user and application management, login history, audit inspection, policy configuration, token revocation, and application-secret reset.

## Technology

- Vue 3 Composition API with TypeScript
- Vite build pipeline
- Element Plus components
- Axios API client
- CSS design tokens and responsive layouts

## Runtime branding

`src/SignaCore.Host/Program.cs` reads `APP_TITLE`, injects it into the generated `index.html`, and sets `window.__APP_TITLE__`. The frontend uses that value for the browser title, navigation brand, login page, and session-check view. The canonical fallback is `SignaCore`.

## Navigation

The authenticated shell contains user, application, token, callback/policy, login-history, and audit views. Drawers and modals are keyboard accessible, close consistently, and preserve the current list context after mutations.

## Authentication

Login and logout go through the shared ServiceMantle management session (`/management/v1/session/login` and `/management/v1/session/logout`, both sent with the `X-ServiceMantle-Request` header); the session itself is read from `/api/admin/session/me`. The session cookie is non-persistent. The client centralizes unauthorized handling, returns to the login view on expiry, and never persists plaintext credentials or application secrets. Newly created or reset application secrets are displayed once in a dedicated secret modal.

## API areas

| Area | Representative routes |
| --- | --- |
| Session | `/management/v1/session/login`, `/api/admin/session/me`, `/management/v1/session/logout` |
| Users | `/api/admin/users`, phone creation, remark/nickname/status updates |
| Applications | `/api/admin/apps`, callback, SMS/LDAP policies, secret reset |
| Security | token revocation, login history, and audit logs |

## State and errors

Composables own session, user, application, token, clock, navigation, and overlay state. Mutations expose loading state, prevent duplicate submission, show actionable errors, and refresh only the affected data. API errors are presented without exposing raw server internals.

## Accessibility and responsive behavior

Interactive controls require labels and visible focus. Modals trap focus and support Escape. Status must not rely on color alone. Desktop tables collapse into usable narrow-screen layouts without horizontal loss of critical actions.

## Build acceptance

```bash
npm ci
npm run test:coverage
npm run build
```

The production build must complete with TypeScript checks, reference the `signacore-admin` package identity, use `SignaCore` as the branding fallback, and contain no former product identifiers.
