# OAuth 2.0 / OpenID Connect Conformance

SignaCore exposes two token surfaces:

| Surface | Route | Shape | Status |
| --- | --- | --- | --- |
| Standards | `/oauth2/token`, `/oauth2/revoke` | RFC 6749 / RFC 7009 | What discovery advertises; use this for new integrations |
| Legacy | `/api/auth/token`, `/api/auth/revoke` | JSON, camelCase, HTTP 200 with `success=false` | Frozen contract for existing consumers |

Both run the same issuance pipeline (`TokenIssuanceService`), so authentication policy, auditing, metrics,
and lockout behave identically; only the wire format differs.

**This page describes the current runtime.** SignaCore is now an OpenID Connect provider for a
narrow, first-party profile: a pre-registered confidential BFF can complete the Authorization Code
flow with mandatory PKCE S256 and receive an ID token. The scope-controlled UserInfo endpoint is
delivered, so `userinfo_endpoint` is advertised. The interactive refresh token family is delivered
too: `offline_access` at the code endpoint creates a rotating refresh family whose replay revokes
its live descendants, and `offline_access` is advertised in Discovery.

## The standards endpoint

### `POST /oauth2/token`

- Body: `application/x-www-form-urlencoded`, read once and bounded: at most 16 KiB counted on the
  bytes actually read (never on the declared `Content-Length`), one strict UTF-8 decode, one
  percent-decode. Duplicate fields keep their cardinality for the existing field rules; unknown
  fields remain ignored by the grants.
- A body past the bound, a non-UTF-8 charset, a compressed body, or malformed percent/UTF-8 is
  rejected with the fixed `400 {"error":"invalid_request","error_description":"The form request is
  invalid."}` — no-store/no-cache, no input echoed, no client lookup or secret verification. An
  unreadable body answers the fixed `503 server_error`. Both answers come only after the shared
  phase and rate-limit budget admit the request; a rejected request consumes nothing. A non-form
  media type never selects the action and keeps MVC's action-selection `415` unchanged.
- Client authentication: `client_secret_basic` (HTTP Basic) or `client_secret_post`
  (`client_id`/`client_secret` form fields). The legacy `X-Admin-AppId`/`X-Admin-AppSecret` headers are
  **not** accepted here.
- Success: HTTP 200, `Cache-Control: no-store`, body with `access_token`, `token_type: "Bearer"`,
  `expires_in`, and `refresh_token`.
- Failure: HTTP 400 with `{"error": "...", "error_description": "..."}`, except client-authentication
  failure which is HTTP 401 with `WWW-Authenticate: Basic` and `error=invalid_client`.

Grant names follow RFC 6749 §4.5 — extension grants are absolute URIs:

| Login method | `grant_type` at `/oauth2/token` | `grant_type` at `/api/auth/token` |
| --- | --- | --- |
| Password | `password` | `password` |
| Refresh | `refresh_token` | `refresh_token` |
| SMS | `urn:signacore:params:oauth:grant-type:sms` | `sms` |
| LDAP | `urn:signacore:params:oauth:grant-type:ldap` | `ldap` |
| WeChat | `urn:signacore:params:oauth:grant-type:wechat-code` | `wechat_code` |

The short names are rejected at `/oauth2/token` with `unsupported_grant_type`. Extension grants take
their credentials in the form body: `phone`/`code` for SMS, `code` for WeChat, `username`/`password`
for LDAP.

`scope` is not supported. A request that carries one is rejected with `invalid_scope` rather than
silently ignored, so a client never receives a token whose authority differs from what it asked for.

### `POST /oauth2/revoke`

RFC 7009: form-encoded, client-authenticated, and always HTTP 200 for a syntactically valid request
whether or not the token existed. Only refresh tokens can be revoked — access tokens are self-contained.

The endpoint shares `/oauth2/token`'s single bounded form read (16 KiB on the bytes actually read,
one strict UTF-8 single-percent decode): an oversized, compressed, or malformed encoding is the same
fixed `400 invalid_request`, an unreadable body the same fixed `503`, both after the shared budget
admits the request, and the Basic credential path cannot bypass the read bound.

Per RFC 7009 §2.1 a token is revoked only when it was issued to the authenticated client; a request
naming another client's token succeeds with HTTP 200 and changes nothing, so the response never reveals
whether a token exists or who owns it.

## The interactive Authorization Code flow

`GET /oauth2/authorize` and the `authorization_code` grant at `POST /oauth2/token` implement the
interactive core for a pre-registered confidential BFF (`PerApplication` audience mode, code flow
enabled) and are advertised in both discovery documents:

- `authorization_endpoint`, `response_types_supported: ["code"]`,
  `code_challenge_methods_supported: ["S256"]`, `grant_types_supported` includes
  `authorization_code`, and `scopes_supported: ["openid", "profile", "offline_access"]`.
- A successful redemption returns `access_token` (`typ: at+jwt`, 15 minutes, audience = the
  application AppId), `id_token` (`typ: JWT`, RS256, 5 minutes, audience = the client id), the
  canonical `scope`, and `expires_in`, with `Cache-Control: no-store`; an `offline_access`
  redemption additionally returns a one-shot `refresh_token` that names a rotating family.

The ID token carries `iss`, stable `sub`, `aud`, `exp`, `iat`, the session's `auth_time`, `sid`,
`amr: ["pwd"]`, and the exact authorization-request `nonce`; `name`/`nickname` appear only when
`profile` was granted. It never carries roles, permissions, or callback claims. A BFF consuming it
must validate the RS256 signature through the `kid`-selected JWKS key, the exact issuer, its own
audience, the lifetime, the `typ`, and the one-time `nonce`, and must keep every token server-side.
A refresh at `POST /oauth2/token` with `grant_type=refresh_token` rotates the family atomically and
returns a new access token, a nonce-free ID token, and exactly one new refresh token; replaying a
consumed member revokes every live descendant of the family and answers `invalid_grant`.

## Access-token audience

`aud` is controlled per application by `app_registrations.audience_mode`:

| Mode | `aud` | Meaning |
| --- | --- | --- |
| `Shared` (default) | `Jwt:Audience` | Every application receives the same audience, so **an access token issued to one application also validates at every other one** |
| `PerApplication` | the application's `app_id` | The audience is a real boundary |

`Shared` remains the default so existing downstream validators keep working. Migrate one application at
a time:

1. Configure the downstream service to accept **both** `Jwt:Audience` and its own AppId.
2. Flip the application to `PerApplication`
   (`PUT /api/admin/apps/{appId}/audience-mode`, or the admin console app drawer).
3. Remove the shared audience from the downstream validator.

Reversing step 2 is safe at any point; tokens already issued keep the audience they were signed with
until they expire.

**Scope of the isolation.** `PerApplication` constrains *downstream* resource servers, which validate
with their own configured audience. SignaCore's own `/api/profile/*` endpoints deliberately accept any
token this service issued, regardless of mode: they are per-user self-service, not owned by one
application, so a user holding a token from any registered application may manage their own profile.
Application-scoped decisions on those endpoints — such as which application a WeChat binding admits —
are made from the `client_id` claim, not from `aud`.

## What conforms today

| Area | Status |
| --- | --- |
| Signing algorithm | RS256 with key rotation |
| JWKS publication (RFC 7517) | Conforms; all unexpired keys are served during rotation. Served at `/.well-known/jwks` (what discovery advertises) and at the de-facto `/.well-known/jwks.json`, which returns the identical document |
| Access-token claims | `iss`, `aud`, `sub`, `exp`, `nbf`, `iat`, `jti`, `client_id` with standard names |
| Access-token type (RFC 9068) | `typ: at+jwt` |
| Token endpoint (RFC 6749 §3.2) | Conforms at `/oauth2/token` |
| Client authentication (RFC 6749 §2.3.1) | `client_secret_basic`, `client_secret_post` |
| Error responses (RFC 6749 §5.2) | Conforms at `/oauth2/*` |
| Extension grant naming (RFC 6749 §4.5) | Absolute URIs |
| Authorization Code + PKCE (RFC 6749 §4.1, RFC 7636) | Confidential-BFF interactive flow with mandatory S256; code redemption is atomic with replay detection |
| ID tokens (OIDC Core 1.0 §2) | RS256, 5 minutes, `nonce`/`auth_time`/`sid`/`amr`, closed claim set; `id_token_signing_alg_values_supported: ["RS256"]` |
| Revocation (RFC 7009) | Conforms at `/oauth2/revoke` |
| Discovery (RFC 8414) | Served at `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`; advertises only endpoints and grants that exist |
| Refresh-token rotation | Single-use rotation with atomic consumption |
| Refresh-token storage | Versioned one-way SHA-256 digest; raw bearer tokens are returned once and never persisted |
| Audience isolation | Available per application; `Shared` by default |

## What does not conform

| Gap | Specification | Impact |
| --- | --- | --- |
| ID tokens only for the interactive flow | OIDC Core 1.0 §2 | `id_token` exists for the confidential-BFF Authorization Code flow only; the direct credential grants keep returning access tokens alone |
| UserInfo is interactive-flow-only | OIDC Core 1.0 §5.3 | `GET /oauth2/userinfo` serves the closed `PS-16` claim set to a confidential BFF holding a live interactive access token; it is not a browser endpoint (no CORS) and does not serve direct-grant tokens |
| No `scope` on the direct grants | RFC 6749 §3.3 | The direct credential grants have no way to request or restrict a subset of authority; the interactive flow's scope is fixed by the registration allow list |
| The `password` grant is the primary flow | OAuth 2.1 draft, BCP 240 | The resource-owner password grant is deprecated in current guidance; it remains here because clients depend on it |
| Legacy grants lack reuse detection | OAuth 2.0 Security BCP §4.14 | Interactive refresh families rotate atomically and revoke live descendants on replay; the legacy `refresh_token` grant keeps its current rotation without that guarantee (`EV-33`) |
| Development `Jwt:Issuer` defaults to `SignaCore` | RFC 8414 §2 | Development remains convenient; production startup requires an absolute HTTPS issuer unless an explicit temporary legacy override is enabled |
| Legacy `/api/auth/*` routes | RFC 6749 | Kept deliberately; not standards-shaped and not advertised in discovery |

## Target design, not current behavior

The [interactive OIDC target design](../oidc/README.md) closes the design-level gaps for a
pre-registered confidential BFF using Authorization Code with mandatory PKCE S256, ID/access-token
separation, database-backed identity sessions, UserInfo, prepared logout, and interactive refresh
families. Its [canonical semantic model](../oidc/CanonicalSemanticModel.md) is normative for the
future implementation. The design documents do not add routes, metadata, database objects, or
runtime guarantees.

Future metadata changes are governed by the
[Discovery activation graph](../oidc/Discovery.md). In particular, the core authorization capability
is advertised only after the end-to-end code and ID-token slice is usable; UserInfo and
`offline_access` are published later. Prepared logout intentionally does not publish a standard
`end_session_endpoint`. The [security contract](../oidc/Security.md) remains a production release
gate even after individual routes exist.

The target follows [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html),
[OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html),
[RFC 6749](https://www.rfc-editor.org/rfc/rfc6749),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636),
[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414),
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207), and
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700). Its prepared logout transport is not a claim of
RP-Initiated Logout conformance.

## Deployment guidance

- Production startup requires `Endpoints:PublicBaseUrl` to be the externally reachable HTTPS origin,
  preventing discovery metadata from depending on an untrusted request `Host`. Development can still
  derive discovery URLs from the incoming request.
- Set `Jwt:Issuer` to the same absolute https URL that clients use to fetch discovery. Changing the
  issuer invalidates the issuer check in every downstream validator configured with the old value, so
  treat it as a coordinated migration, not a config tweak.

## Compatibility position

The `/api/auth/token` contract (JSON body, camelCase fields, HTTP 200 with `success=false`) is published
and has downstream consumers, documented in
[Auth/GetToken](../modules/Auth/GetToken/06-CONVENTIONS.md). It is frozen, not deprecated: new
conformance work is added at `/oauth2/*` rather than changing it.
