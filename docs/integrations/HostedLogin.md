# Hosted Login Integration Guide

This guide is for a consuming service that renders its own login page today and sends user
credentials to SignaCore through the Password or SMS token grants. It replaces that page with
SignaCore's hosted login page: the service redirects the browser to SignaCore, the user signs in
there, and the service receives only a one-time authorization code at its registered callback. The
service never sees or stores a user password.

The guide describes behavior that SignaCore delivers today. It is written for server-side
applications first and covers mobile applications in [Mobile applications](#mobile-applications).
The appearance, language, and security headers of the login page itself are described in
[Identity Login](../oidc/IdentityLogin.md); the [Reference BFF](../../samples/SignaCore.ReferenceBff/README.md)
and the [Public SPA sample](../../samples/SignaCore.PublicSpa/README.md) are runnable examples of the
flow below. The examples use a neutral service named `OrderService` at `https://orders.example`;
values in angle brackets are placeholders.

**Recommended: the official client package.** An ASP.NET Core service does not need to implement
the steps below by hand. The [`SignaCore.Client.AspNetCore`](https://www.nuget.org/packages/SignaCore.Client.AspNetCore)
package implements steps 3–7 over the same public HTTP contract — Discovery with issuer
verification, the authorization request with server-side `state`/`nonce` and PKCE S256, the
hardened callback, strict ID-token validation, a capacity-bounded server-side session with its
CSRF boundary, and the prepared logout of step 7 — with every token kept server-side. Its
[README](https://github.com/philfanzhou/SignaCore/blob/main/src/SignaCore.Client.AspNetCore/README.md)
documents the registration, the five extension points (authorization decision, return URL
validation, route prefix, response format, scheme selection), and the session-store replacement
for multi-instance deployments. The steps below remain the authoritative description of the
wire contract the package speaks, and they are what a service on another stack implements
directly.

## Choose a client type

| Client type | Use it for | Holds |
| --- | --- | --- |
| **Confidential** (preferred) | A server-side application, or a mobile application through its own backend | A client secret and every token, server-side only |
| **Public** | A browser single-page application, or a native mobile application with an HTTPS App Link / Universal Link callback | No secret; tokens in the client's memory |

A Confidential client can use every capability in this guide. A Public client cannot revoke
tokens or use prepared logout, and its tokens are exposed to any script or code running in the
client. High-privilege applications should be Confidential.

## 1. Register the application

A SignaCore administrator registers the application through the `/admin` console or the management
API with an administrator session (see the
[application-management specification](../modules/Admin/AppManagement/02-SPEC.md)). The order of
steps 2–4 matters: enabling the Code flow fails while the audience is `Shared` or no redirect URI is
registered, and neither failure repairs the configuration.

1. **Create the application.** `POST /api/admin/apps` with
   `{"appName":"OrderService","callbackUrl":null,"ttlSeconds":0,"clientType":"Confidential"}`
   (`"Public"` for a Public client). Store the returned `appId` as the client id and the one-time
   `appSecret` of a Confidential client in the service's protected secret store; it cannot be read
   again. A Public application has no secret. A claims callback (`callbackUrl`) is unrelated to the
   redirect URI and is never used as one.
2. **Use a per-application audience.** `PUT /api/admin/apps/{appId}/audience-mode` with
   `{"mode":"PerApplication"}`. Migrate existing downstream validators first; see
   [step 2](#2-migrate-the-access-token-audience).
3. **Register the exact callback.** `POST /api/admin/apps/{appId}/oidc/redirect-uris` with
   `{"kind":"Redirect","uris":["https://orders.example/signin-oidc"]}`. A redirect URI is an
   absolute HTTPS URI of at most 500 ASCII characters with no fragment, user info, or wildcard, and
   at most ten are registered per kind. Registration lowercases the scheme and host, removes a
   default port, and turns an empty path into `/`; requests are then compared with the stored value
   byte for byte, so a trailing slash, path case, or query difference does not match. Custom URI
   schemes are rejected. Development alone also accepts `http://127.0.0.1:<port>` and
   `http://[::1]:<port>`; `localhost` is always rejected. To return users somewhere after sign-out,
   register a post-logout URI the same way with `"kind":"PostLogout"`.
4. **Enable the Code flow.** `PUT /api/admin/apps/{appId}/oidc-policy` with
   `{"clientType":"Confidential","allowAuthorizationCode":true,"allowedScopes":["openid","profile"],"allowRefreshToken":false,"identitySessionMaxAgeSeconds":null}`.
   - `allowedScopes` always contains `openid`; add `profile` to receive the username and nickname,
     and `offline_access` to receive refresh tokens.
   - `allowRefreshToken: true` enables refresh and requires `offline_access`. A Public client also
     needs `identitySessionMaxAgeSeconds` from 1 to 43200 for refresh.
   - `identitySessionMaxAgeSeconds` optionally forces a new sign-in for this application once that
     many seconds have passed since the user authenticated (at most 12 hours).
5. **Public browser clients only:** register the exact browser Origin with
   `PUT /api/admin/apps/{appId}/oidc/allowed-origins`. It only lets that Origin read the token and
   UserInfo responses; see [Public Origin CORS](../oidc/TokenEndpoint.md#public-origin-cors).
6. **SMS sign-in (optional):** see [SMS sign-in](#sms-sign-in-optional).

Existing SignaCore accounts sign in unchanged; no account needs to be re-created.

## 2. Migrate the access-token audience

The Code flow always issues access tokens whose `aud` is the application's `appId`. If downstream
services of this application still validate the deployment-wide shared audience, follow the
three-step migration in
[Standards Conformance: access-token audience](../overview/StandardsConformance.md#access-token-audience)
before registration step 2: accept both audiences downstream, switch the application to
`PerApplication`, then remove the shared audience. Tokens already issued keep their audience until
they expire.

## 3. Read Discovery

Read `https://<signacore-host>/.well-known/openid-configuration` at startup and take every endpoint
from it instead of hard-coding paths. Check that its `issuer` equals the SignaCore address the
service is configured with. The document provides `authorization_endpoint`, `token_endpoint`,
`userinfo_endpoint`, `revocation_endpoint`, and `jwks_uri`, and advertises
`response_types_supported: ["code"]`, `code_challenge_methods_supported: ["S256"]`, and the
supported scopes. It deliberately has no `end_session_endpoint`; sign-out uses
[prepared logout](#7-sign-out-with-prepared-logout).

## 4. Send the browser to the authorization endpoint

For each sign-in, generate and bind to the browser's pending sign-in, server-side:

- `state` and `nonce`: fresh random values of 22–128 characters from `[A-Za-z0-9._~-]`;
- a PKCE `code_verifier` of 43–128 characters from the same set, and its S256
  `code_challenge` (43 base64url characters without padding).

Redirect the browser to `authorization_endpoint` with the query fields `response_type=code`,
`client_id`, `redirect_uri` (exactly the registered value), `scope` (for example `openid profile`),
`state`, `nonce`, `code_challenge`, and `code_challenge_method=S256`. `prompt`, `max_age`,
`acr_values`, `response_mode`, `request`, `request_uri`, and `registration` are rejected, and each
supported field may appear only once.

SignaCore answers in one of these ways:

- An unknown or inactive client, or a `redirect_uri` that is not registered, is shown as a local
  error page and never redirected.
- If the browser already has a usable SignaCore session for this application, the browser returns
  to the callback immediately without a login page.
- Otherwise the browser sees the hosted login page. After a successful sign-in it returns to
  `redirect_uri?code=...&state=...&iss=...`. If the user selects Cancel, it returns with
  `error=access_denied`, `state`, and `iss`; other request errors such as `invalid_scope` return
  the same way.

The hosted page uses a consistent SignaCore card in English or Simplified Chinese (selected only
by `Accept-Language`) and follows the browser's light/dark preference. Password and optional SMS
remain separate, directly visible forms. Primary sign-in actions occupy the form width; Cancel
stays secondary and works with empty fields. The OTP/send row wraps on narrow screens. Notices
appear within the method's form, with a uniform neutral SMS-send notice regardless of delivery
outcome. The page needs no scripts or external assets and remains usable without CSS.

At the callback, reject the response unless `state` matches the pending sign-in and `iss` equals
the Discovery `issuer`, then discard the pending values after one use. Treat the code as a secret:
keep it out of logs and analytics.

## 5. Redeem the code and validate the tokens

Within 60 seconds, send `POST token_endpoint` from the server as
`application/x-www-form-urlencoded` with `grant_type=authorization_code`, `code`, the same
`redirect_uri`, and `code_verifier`. A Confidential client authenticates with HTTP Basic
(`client_secret_basic`) or with `client_id`/`client_secret` form fields (`client_secret_post`),
never both. A Public client sends only `client_id` in the form. Do not send `scope`. A code is
single-use: presenting it again answers `invalid_grant` and signs the user's SignaCore session out.

A successful response contains `access_token`, `token_type: Bearer`, `expires_in` (900 seconds for
a Confidential client, 300 for a Public client), `id_token`, the granted `scope`, and a
`refresh_token` only when `offline_access` was granted. Failures use the standard `error` and
`error_description` fields.

Validate the ID token before creating a local session: RS256 signature through the JWKS key named
by its `kid`, `typ: JWT`, `iss` equal to the Discovery issuer, `aud` equal to the client id,
`exp`/`iat`, and `nonce` equal to the pending value. Its claims are `sub` (the stable SignaCore
account id), `auth_time`, `sid`, and `amr` (`["pwd"]` for a password sign-in, `["sms"]` for an
[SMS sign-in](#sms-sign-in-optional)), plus `name` (the SignaCore username) and `nickname` when
`profile` was granted. After an SMS sign-in, `name` appears only when the account has exactly one
SignaCore username. Key the local user by `iss` plus `sub`; the ID token carries no roles or
permissions, so authorization stays the service's own decision.

The official client package optionally gates new callback sessions with
`PreSignInAuthorizationDecision` (default null). When configured, it strictly validates the
SignaCore access token and correlates its verified issuer/subject with the ID token before calling
your decision on request-local claim copies. Only timely Allowed creates a ticket/cookie; denial,
exceptions, or timeout leave existing sessions unchanged, and request cancellation propagates.
This differs from `AuthorizationDecision`, which only reports authorization at session-status read
and retains an authenticated session on denial. See the
[package gate and migration guide](../../src/SignaCore.Client.AspNetCore/README.md#optional-authorization-before-sign-in)
for timeout, cancellation, expiry, consumer responsibilities, and rollback. Pure HTTP integration
and downstream Bearer validation remain unchanged.

Call downstream services with the access token as a Bearer credential. They validate it as before —
signature through JWKS, issuer, audience (the application's `appId`), lifetime, and `typ: at+jwt` —
without calling SignaCore. `GET userinfo_endpoint` with the access token returns `sub` and, with
`profile`, `name` (under the same rule as the ID token) and `nickname`. No token or UserInfo response
ever carries the user's phone number.

## 6. Refresh tokens (optional)

With `offline_access`, send `POST token_endpoint` with `grant_type=refresh_token` and the current
`refresh_token`, authenticated as in step 5 and without `scope`. Each refresh returns a new access
token, a new ID token without `nonce`, and a new refresh token; the old one is spent. Presenting a
spent refresh token again answers `invalid_grant` and revokes every refresh token issued after it,
so two parts of the service must never share one refresh token. A refresh token lasts at most seven
days and never outlives the user's SignaCore session (see [Session lifetime](#8-session-lifetime));
for a Public client it also ends at the application's maximum session age. A Confidential client
can revoke a refresh token with `POST revocation_endpoint`; a Public client cannot.

## 7. Sign out with prepared logout

Prepared logout ends the user's SignaCore session and is available to Confidential clients only.
It keeps the ID token off the browser:

1. Clear the service's own session, then send `POST /oauth2/logout/requests` from the server with
   the same client authentication as the token endpoint and the form fields `id_token_hint` (an ID
   token SignaCore issued to this client for this user, at most 24 hours old; expiry is ignored
   here), an optional `post_logout_redirect_uri` exactly matching a registered post-logout URI, and
   an optional `state` (22–128 characters from `[A-Za-z0-9._~-]`).
2. The JSON response contains `logout_uri`. Redirect the browser to it within five minutes; it
   works once.
3. SignaCore ends the session bound to that browser and redirects to `post_logout_redirect_uri`
   with the same `state`, or shows its own signed-out page when none was given. The answer looks the
   same whether or not the browser still had that session, so do not infer anything from it.

The whole contract, including error answers, is in [Prepared Logout](../oidc/Logout.md). The
Reference BFF demonstrates this flow end to end through the client package. A
Public client cannot use prepared logout: signing out only forgets its tokens, and a later sign-in
may complete without a login page while the SignaCore session is still valid.

Applications using the [official client package]
(https://www.nuget.org/packages/SignaCore.Client.AspNetCore) get prepared logout from the package:
`GET <prefix>/csrf` issues the antiforgery token, `POST <prefix>/logout` revokes the local
server-side session first and then performs the preparation above on the backchannel, and
`GET <prefix>/logout/return` consumes the one-time echoed state and redirects to the consumer's
fixed landing path. The package's own README documents the exact options
(`PostLogoutRedirectUri`, `PostLogoutReturnPath`, `AntiforgeryHeaderName`); the ID token and
client secret never leave the server side of the consuming application.

## 8. Session lifetime

The SignaCore session behind a sign-in lasts at most 12 hours and ends after 30 minutes without
activity. Only a successful authorization request from the browser counts as activity (recorded at
most once per minute, never beyond 12 hours); signing in, refreshing, calling UserInfo, and
preparing logout do not extend it. This has direct consequences:

- A refresh token stops working when the session ends: after 30 minutes without a browser
  authorization request, or 12 hours after sign-in, refresh answers `invalid_grant` and UserInfo
  answers `401 invalid_token`. Refresh never extends the session.
- A service that wants users to stay signed in longer keeps its own session. When it needs fresh
  SignaCore tokens, it sends the browser through the authorization endpoint again: while the
  SignaCore session is usable the browser returns immediately; otherwise the user signs in again.
- `identitySessionMaxAgeSeconds` shortens the limit for one application only.
- Access tokens already issued stay valid downstream until their own expiry (15 minutes for a
  Confidential client, 5 minutes for a Public client), even after sign-out or account
  deactivation. A downstream service that needs an immediate cut-off must check state itself.

## SMS sign-in (optional)

The hosted page can also sign users in with a mainland China mobile number and a one-time code sent
by SMS. It is enabled per application with `PUT /api/admin/apps/{appId}/sms-policy` and
`{"mode":"<ManualApproval|AutoProvision>","profileKey":"<profile>"}`, where `profileKey` names a
configured SMS provider profile (`GET /api/admin/sms/profiles` lists them). The page shows the SMS
form only while the mode is not `Disabled` and a profile is set; otherwise it offers the password
form alone.

- `ManualApproval` admits only phones an administrator added to the application
  (`POST /api/admin/apps/{appId}/sms-users`).
- `AutoProvision` also admits a new phone: the first successful sign-in creates the SignaCore
  account and admits it to the application. Requesting a code never creates anything.
- Revoking a phone (`DELETE /api/admin/apps/{appId}/sms-users/{loginId}`) or setting the mode to
  `Disabled` stops that application from using the phone's SignaCore session at its next
  authorization request, code exchange, refresh, or UserInfo call, without affecting other
  applications.

The page answers every code request with the same notice — "if this phone number can sign in to
this application, a verification code has been sent" — whether or not a code was actually sent, and
every failed SMS sign-in with the same failure notice. This prevents the page from revealing which
numbers are registered or admitted, at a user-experience cost the service should explain in its own
help text: a user whose number cannot sign in sees the same notice as everyone else and receives no
code. Code requests are limited per sign-in attempt, per network, and per phone, and the response
time is not made uniform. The SMS token grant's bypass code never works on the hosted page.

An SMS sign-in issues the same code, tokens, and session as a password sign-in, with
`amr: ["sms"]` and the `name` rule above. The service must accept both `amr` values and must not
expect a phone number in any token.

## Mobile applications

Mobile applications use the system browser component, never an embedded WebView. Custom-scheme
redirect URIs are not supported.

**Through the application's own backend (preferred).** The backend is a Confidential client and
runs steps 3–7 exactly as a server-side application, with its HTTPS callback on the backend. The
mobile application opens the backend's sign-in address in the system browser component (for
example `ASWebAuthenticationSession` on iOS or Custom Tabs on Android) and, after the callback,
receives the backend's own session for its API calls. The client secret and SignaCore tokens never
reach the device, the backend can use prepared logout, and the backend's own session can outlast
the 30-minute idle limit.

**As a Public client.** The application itself runs steps 3–6 with PKCE S256 and a registered HTTPS
redirect URI that the platform routes to the application as an App Link (Android) or Universal Link
(iOS). The limits are:

- no `/oauth2/revoke` and no prepared logout; signing out only discards the tokens on the device;
- access tokens last 5 minutes, and refresh needs the explicit refresh policy and a maximum session
  age from registration step 4;
- registered Origins only control whether a browser page may read responses; the application's own
  HTTP code exchange does not depend on an Origin and needs none registered;
- tokens on the device are exposed to anything that can run code in the application.

SignaCore does not guarantee that a redirect to an HTTPS callback is handed to the application
instead of being opened as a web page. That depends on the platform and the browser component: for
example, `ASWebAuthenticationSession` completes HTTPS callbacks only on recent iOS versions, and
Android App Links require a verified domain association. Verify the callback on every target
platform and OS version. SignaCore does not provide a mobile SDK.

## Migrating from the Password or SMS grants

1. Register the application and enable the Code flow as in step 1, after migrating downstream
   audiences as in step 2. The existing grants keep working for the same application during the
   migration.
2. Build the authorization request, callback, code exchange, and token validation of steps 3–5 in
   the service, and keep tokens server-side.
3. Map local users to `iss` plus `sub`. Existing access tokens from the Password grant already carry
   the same `sub` for the same account, so an existing mapping by `sub` stays valid; with `profile`,
   the ID token's `name` is the SignaCore username.
4. Switch the service's sign-in entry to the authorization endpoint and remove its own login form.
   Users enter credentials only on SignaCore's page.
5. Remove the service's calls to the Password grant and any storage of user credentials. The
   grants themselves stay available to other consumers.

The hosted login page accepts SignaCore username-and-password accounts and, for an application with
[SMS sign-in](#sms-sign-in-optional) enabled, mainland China mobile numbers with a one-time code. A
service whose users sign in through the SMS grant enables SMS sign-in for its application and moves
them to the hosted page: a phone that already signed in through the SMS grant keeps the same
SignaCore account and therefore the same `sub`. Under `ManualApproval` the phone must be admitted to
the application; the SMS grant's admissions for that application carry over unchanged.

## Responsibilities

The service keeps its client secret, PKCE verifiers, `state`/`nonce` values, and tokens out of
browsers, logs, and URLs; validates every callback and ID token as described above; and owns every
authorization decision it makes from `iss` plus `sub`. SignaCore owns credentials, the login page,
the SignaCore session, and token issuance.

Redirect URIs over `http` and `https` are accepted equally in every environment — transport is a
deployment decision ([ADR 0008](../adr/0008-transport-security-is-a-deployment-decision.md)); see
[plain-HTTP deployments](../oidc/HttpTesting.md) and the
[redirect canonical form](../oidc/CanonicalSemanticModel.md#product-stages).
The isolated HTTP identity/CSRF Cookie carrier is also implemented at exact allowed request origins;
official dual-end published-image/browser acceptance remains the complete-capability release gate.

Applications integrating through the official
[`SignaCore.Client.AspNetCore`](https://www.nuget.org/packages/SignaCore.Client.AspNetCore) package
can additionally declare an explicit intranet HTTP deployment on the client side:
`options.IntranetHttpOrigins` holds the exact private-network HTTP origins of the SignaCore host
and of the consumer itself (for example `http://192.168.55.10:5002` and
`http://192.168.55.10:5020`), and the package then accepts those origins — and only those — for
the Authority, the redirect URIs, and every Discovery endpoint, in every environment name
including Production, while writing all its cookies for plain HTTP. The client-side list is the
consumer's own deployment statement and is independent of the host-side Testing-gated list above;
the host must still admit the consumer's HTTP redirect origin from its side. See the package
README's
[intranet HTTP deployments](https://github.com/philfanzhou/SignaCore/blob/main/src/SignaCore.Client.AspNetCore/README.md#intranet-http-deployments-explicit-opt-in)
section for the exact origin grammar, the cookie profile, and the caller responsibilities.
