# SignaCore Public SPA sample

A minimal browser single-page application that signs a user in to SignaCore as an OpenID Connect
**Public client**: Authorization Code with mandatory S256 PKCE, no client secret, and tokens held
only in the page's memory. It uses the published Discovery, authorize, token, and UserInfo
contracts and nothing else.

The sample has no npm dependencies and needs only Node.js 22.12 or later (the same versions as
[Local Setup](../../docs/development/LocalSetup.md)). It is not part of `SignaCore.slnx`.

> **Prefer a BFF for high-privilege applications.** A browser that holds bearer tokens exposes them
> to every script running in the page. Administration consoles and other high-privilege clients
> should use a confidential backend-for-frontend such as the
> [Reference BFF](../SignaCore.ReferenceBff/README.md). Use this Public client pattern only when
> tokens in the browser are an acceptable risk.

| File | Purpose |
| --- | --- |
| `public-client.js` | The protocol: Discovery check, PKCE, callback validation, code exchange, refresh, UserInfo, local sign-out. Browser capabilities are injected so it runs under `node --test`. |
| `app.js`, `index.html` | Buttons and status output. No inline script or style. |
| `serve.mjs` | A development-only static server bound to `127.0.0.1` with a strict Content Security Policy. |
| `test/*.test.mjs` | `node --test` tests of the client and the server. |

## From an empty installation to a signed-in page

Run the commands from the repository root. Values in angle brackets are placeholders; keep
passwords out of shell history and source control.

1. **Start SignaCore in Development.** Follow [Local Setup](../../docs/development/LocalSetup.md)
   and [First-Run Setup](../../docs/development/FirstRunSetup.md), and complete `/setup` with the
   public base URL `http://localhost:5002` and the insecure HTTP issuer option enabled
   (`publicBaseUrl=http://localhost:5002`, `allowNonHttpsIssuer=true`). The loopback HTTP redirect
   URI and Origin below are accepted only in the Development environment.
2. **Create a Public application.** Sign in to `/admin` as the installation administrator and use
   **Applications**, or call the management API with that session:
   `POST /api/admin/apps` with
   `{"appName":"Public SPA sample","callbackUrl":null,"ttlSeconds":0,"clientType":"Public"}`.
   The response carries `appSecret: null`; a Public application has no secret. Keep the returned
   `appId` for step 8.
3. **Use a per-application audience.** `PUT /api/admin/apps/{appId}/audience-mode` with
   `{"mode":"PerApplication"}`.
4. **Register the redirect URI.** `POST /api/admin/apps/{appId}/oidc/redirect-uris` with
   `{"kind":"Redirect","uris":["http://127.0.0.1:5173/callback"]}`. Development loopback redirects
   must use `127.0.0.1`; `localhost` is rejected.
5. **Register the browser Origin.** `PUT /api/admin/apps/{appId}/oidc/allowed-origins` with
   `{"origins":["http://127.0.0.1:5173"]}`. The Origin only lets this page read the token and
   UserInfo responses; it is not a credential.
6. **Enable the Code flow.** `PUT /api/admin/apps/{appId}/oidc-policy` with
   `{"clientType":"Public","allowAuthorizationCode":true,"allowedScopes":["openid","profile"],"allowRefreshToken":false,"identitySessionMaxAgeSeconds":null}`.
   Steps 3 and 4 must come first: with the default `Shared` audience this fails with
   `Authorization Code flow requires a per-application audience.`, and without a redirect URI it
   fails with `Authorization Code flow requires at least one redirect URI.`

   *Optional refresh.* To try refresh rotation, update the same policy to
   `{"clientType":"Public","allowAuthorizationCode":true,"allowedScopes":["openid","profile","offline_access"],"allowRefreshToken":true,"identitySessionMaxAgeSeconds":900}`
   and start the sample with `SIGNACORE_SPA_SCOPE="openid profile offline_access"` in step 8.
   Choose the shortest session maximum age that works for you (1–43200 seconds); the refresh
   family ends no later than that age after sign-in.
7. **Create an account.** In **Users**, or with `POST /api/admin/users` and
   `{"username":"<account-name>","password":"<password>","displayName":null,"remark":null,"nickname":null}`.
   Enter this password only on SignaCore's login page; the sample never receives it.
8. **Start the sample.**

   ```bash
   SIGNACORE_AUTHORITY=http://localhost:5002 \
   SIGNACORE_SPA_CLIENT_ID=<appId> \
   node samples/SignaCore.PublicSpa/serve.mjs
   ```

   The server reads Discovery at startup and exits if its `issuer` is not exactly
   `SIGNACORE_AUTHORITY`. Open `http://127.0.0.1:5173/` (not `localhost`, which is a different
   Origin).
9. **Try it.**
   - **Sign in** goes to SignaCore's login page and returns to `/callback`; the page shows the
     subject, the username, and the access-token expiry time.
   - **Read UserInfo** calls `GET /oauth2/userinfo` with the in-memory access token.
   - **Refresh tokens** (with the optional refresh policy) rotates the refresh token once.
   - **Sign out of this page** forgets the tokens in this page (see the limits below).
   - Error example: select **Sign in**, then **Cancel** on SignaCore's login page. The page
     returns with `Error: access_denied` and no token request is sent.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SIGNACORE_AUTHORITY` | — | SignaCore's public base URL; must equal the Discovery `issuer` exactly |
| `SIGNACORE_SPA_CLIENT_ID` | — | The Public application's `appId` |
| `SIGNACORE_SPA_PORT` | `5173` | Local port; the redirect URI is `http://127.0.0.1:<port>/callback` |
| `SIGNACORE_SPA_SCOPE` | `openid profile` | Requested scope; must contain `openid` |

`/config.json` publishes only these non-sensitive values and the Discovery endpoints. There is no
client secret to configure.

## How the page handles credentials

- **Memory only.** Access, refresh, and ID tokens live in `public-client.js` module memory. A
  reload or closed tab loses them and the user signs in again. Nothing is written to
  `localStorage`, cookies, or the URL fragment, and every request uses `credentials: 'omit'`.
- **One pending login in `sessionStorage`.** To survive the redirect to SignaCore, the page stores
  one `{state, nonce, code_verifier, createdAt}` record. The callback deletes it before any
  validation or request, whatever the outcome, and it expires after 10 minutes.
- **Callback checks before any request.** The callback removes `code`, `state`, and `iss` from the
  address bar with `history.replaceState`, then requires exactly one of `code` or `error`, the
  exact `state`, and an `iss` equal to the Discovery issuer. Any failure sends no token request.
- **Code exchange.** `POST /oauth2/token` with exactly `grant_type`, `client_id`, `code`,
  `redirect_uri`, and `code_verifier`, and no `Authorization` header.
- **ID token.** The page checks `iss`, a single-valued `aud` equal to the client id, `exp`, and the
  `nonce`, then keeps only `sub` and `name` for display. It does not verify the signature: the ID
  token comes directly from the token endpoint over TLS, which
  [OpenID Connect Core 1.0 §3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
  item 6 permits. The ID token is never an API credential.
- **Refresh.** Concurrent refresh calls share one request. A 200 replaces the access and refresh
  tokens together; any other status, a network failure, an unreadable response, or a cancelled
  request clears the session. The sample never sends a refresh token twice, because SignaCore
  treats a replay as theft and revokes the family.
- **UserInfo.** A 401 triggers at most one refresh and one retry.
- **Display.** The page shows `sub`, `name`, and expiry times only; it never displays or logs a
  token or the verifier.

A downstream API must validate the access token itself: the RS256 signature through SignaCore's
JWKS, the issuer, the lifetime, and an audience equal to **its own** AppId, as in a
per-application audience setup. An access token issued to this sample does not validate for
another application's audience.

## What the sample does not guarantee

- It does not protect tokens from cross-site scripting or other script running in the page's
  Origin, from a token stolen before first use, or from non-browser callers.
- **Sign out of this page only clears this page.** It does not revoke the refresh family — Public
  clients cannot call the revocation endpoint — so the family remains valid until it expires, at
  most the application's session maximum age after sign-in. It also does not end the SignaCore
  identity session — prepared logout is limited to Confidential clients — so signing in again
  while that session is valid may not ask for the password.
- An issued access token stays valid until its own `exp` (300 seconds for a Public client).
- `serve.mjs` is not a production web server.

## Production requirements

- Serve the page and SignaCore over HTTPS, and register the page's exact HTTPS Origin and redirect
  URI. Development loopback HTTP is not accepted outside the Development environment.
- Deploy an equivalent Content Security Policy and script isolation: scripts only from your own
  Origin, `connect-src` limited to your Origin and SignaCore, no framing, and no third-party script
  in the page that holds tokens.
- Keep tokens in memory for the shortest practical time. Prefer no refresh at all, or the shortest
  workable `identitySessionMaxAgeSeconds`.
- On shared devices, ending the SignaCore session needs an administrator to revoke the identity
  session, or the browser to be closed.
- Downstream APIs validate access tokens through JWKS with their own audience.
- Use a confidential BFF for high-privilege administration.

## The development server

`serve.mjs` binds `127.0.0.1` only, answers `GET` for `/`, `/callback`, `/app.js`,
`/public-client.js`, and `/config.json`, and returns `404` for every other path, method, or
`Host`. Every response carries:

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self' <SignaCore token/UserInfo origin>; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
Cache-Control: no-store
X-Content-Type-Options: nosniff
```

## Tests

```bash
node --test 'samples/SignaCore.PublicSpa/test/*.test.mjs'
```

CI runs the same command. The end-to-end HTTP contract against a real SignaCore host, following
the registration order above, is
`tests/SignaCore.IntegrationTests/Integration/PublicSpaSampleFlowTests.cs`.
