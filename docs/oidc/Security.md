# Security Contract

**Status: target design.** See [README](./README.md).

Everything here is a requirement on the implementation, and every row of the attack matrix is meant
to become a test.

## Attack matrix

| Attack | Defence | Where it is specified | Test shape |
| --- | --- | --- | --- |
| Open redirect from the authorization endpoint | Nothing is redirected until `client_id` and `redirect_uri` are both verified | [AuthorizationEndpoint](./AuthorizationEndpoint.md#error-routing) | Unregistered `redirect_uri` → 400, no `Location` header |
| Redirect URI substitution | Exact ordinal match, no normalization at request time, no wildcards | [ClientModel](./ClientModel.md#request-time-comparison) | Each row of the comparison table |
| Authorization code interception | PKCE `S256`, mandatory, no `plain`, no per-client toggle | [TokenEndpoint](./TokenEndpoint.md#verification-order) | Wrong `code_verifier` → `invalid_grant` |
| PKCE downgrade | `code_challenge_method` must be exactly `S256`; absence and `plain` both fail | [AuthorizationEndpoint](./AuthorizationEndpoint.md#request-parameters) | `plain`, empty, and absent all → `invalid_request` |
| Code replay | Atomic conditional consumption; a second redemption revokes the first's refresh family and the session | [TokenEndpoint](./TokenEndpoint.md#replay-handling) | Sequential and concurrent redemption |
| Refresh token replay | Family model; reuse revokes every live descendant | [Tokens](./Tokens.md#reuse-detection) | Replay a rotated token, assert descendants die |
| Code injection into another client | The code's client must equal the authenticated client | [TokenEndpoint](./TokenEndpoint.md#verification-order) | Client B redeems A's code → `invalid_grant` |
| ID token replay | `nonce` required, echoed verbatim, verified by the client; 5-minute lifetime | [Tokens](./Tokens.md#id-token) | Reused `nonce` rejected by the client |
| Cross-client token acceptance | `aud` is one `client_id`; `PerApplication` audience is required for interactive clients | [Tokens](./Tokens.md), [ClientModel](./ClientModel.md#audience) | A's token rejected at B |
| Mix-up between issuers | `iss` on every authorization response, success and error (RFC 9207) | [AuthorizationEndpoint](./AuthorizationEndpoint.md#success-response) | `iss` present in both cases |
| CSRF on the client's callback | `state` required, echoed byte-for-byte | [AuthorizationEndpoint](./AuthorizationEndpoint.md#request-parameters) | Missing `state` → `invalid_request` |
| Session revocation by a bearer of an ID token | Logout revokes only when the request's identity cookie names the session in `id_token_hint` | [Logout](./Logout.md#processing) | Hint replayed without the cookie → session survives, response still succeeds |
| Login CSRF | Antiforgery token on the login POST, `__Host-` cookie, independent of the session | [IdentitySession](./IdentitySession.md#login-csrf) | POST without token → 400 |
| Session fixation | A new session identifier is generated on every successful login; a pre-existing cookie is never reused | This document | Cookie value differs before and after login |
| Cookie theft via script | `HttpOnly`, `__Host-` prefix, `Secure` | [IdentitySession](./IdentitySession.md#cookie-attributes) | Attribute assertions on `Set-Cookie` |
| Cookie sent cross-site | `SameSite=Lax`; the only cross-site entry is a top-level idempotent GET | [IdentitySession](./IdentitySession.md#cookie-attributes) | Attribute assertion |
| Subdomain cookie injection | `__Host-` prefix forbids `Domain` | [IdentitySession](./IdentitySession.md#cookie-attributes) | Attribute assertion |
| Code leaked through `Referer` | `Referrer-Policy: no-referrer` on every authorization response | [AuthorizationEndpoint](./AuthorizationEndpoint.md#anti-caching-and-referrer) | Header assertion |
| Code leaked through a cache | `Cache-Control: no-store`, `Pragma: no-cache` everywhere | Throughout | Header assertion on every endpoint |
| Code or token in a log | Digests stored; plaintext never logged; scrubbing on the way out | This document | Log-content assertion |
| Timing oracle on redemption | All post-lookup failures return one message; constant-time PKCE comparison | [TokenEndpoint](./TokenEndpoint.md#verification-order) | Identical bodies across causes |
| Account enumeration at login | One generic failure for unknown, wrong, disabled, and locked out | [IdentitySession](./IdentitySession.md#credentials) | Identical bodies across causes |
| Client enumeration at authorize | The local error page does not say whether the `client_id` exists | [AuthorizationEndpoint](./AuthorizationEndpoint.md#error-routing) | Identical bodies for unknown vs. non-interactive |
| Privilege crossover between cookies | Separate schemes, names, and Data Protection purposes; each rejected at the other's endpoints | [IdentitySession](./IdentitySession.md#two-cookies-no-overlap) | Admin cookie at `/oauth2/authorize` → login |
| Session outliving revocation | Server-side session record checked on every request | [IdentitySession](./IdentitySession.md#server-side-session-record) | Revoke on instance A, request on instance B |
| `returnUrl` abuse at the login page | The authorization request is stored server-side behind a single-use handle | [IdentitySession](./IdentitySession.md#login-continuation) | No URL parameter accepts a destination |
| Parameter pollution | A repeated parameter fails before its value is read | [AuthorizationEndpoint](./AuthorizationEndpoint.md#duplicate-parameters) | Duplicated `redirect_uri` → 400 |
| Brute force on codes or credentials | Rate-limit partitions per client, per IP, per subject | Below | Limiter assertions |
| Denial of service through storage growth | Bounded lengths on every field; 24-hour cleanup | [Persistence](./Persistence.md) | Over-length input rejected |

## Values that must never be written down

Never logged, never in an audit record, never in a metric label, never in an exception message,
never in a test fixture that is committed, never returned in an error body:

- Passwords, and anything derived from one other than the stored hash.
- Authorization codes, `code_verifier`, and `code_challenge`.
- Access tokens, ID tokens, refresh tokens.
- Identity-session cookie values and continuation handles.
- Client secrets and `Authorization` header values.
- Signing private keys and the root key.
- OTP codes.

Loggable, because they are identifiers rather than credentials: `client_id`, the account identifier
(`sub`), session identifiers, code record identifiers, `state`, `nonce`, correlation identifiers,
and `redirect_uri`.

`state` and `nonce` are on the loggable side deliberately. Neither is a credential: both are already
in the browser's URL bar, both are client-generated CSRF and replay markers, and having them in the
log is what makes a failed login reconstructable. The `nonce` is stored in plaintext for the same
reason plus a hard one — it must be copied verbatim into the ID token, so a digest would be
unusable.

Scrubbing is enforced by the ServiceMantle log-scrubbing pipeline
(philfanzhou/ServiceMantle#83) and its sensitive-header handling (philfanzhou/ServiceMantle#142);
SignaCore contributes the field names above. See [Ownership](./Ownership.md).

## Response headers

| Endpoint | Headers |
| --- | --- |
| `/oauth2/authorize` | `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer` |
| Login pages | Same, plus `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'` |
| `/oauth2/token` | `Cache-Control: no-store`, `Pragma: no-cache` — unchanged |
| `/oauth2/userinfo` | `Cache-Control: no-store`, `Pragma: no-cache` |
| `/oauth2/logout` | `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer` |

Framing is denied on the login page because a framed login is a clickjacking surface and there is no
legitimate reason to embed an identity provider's credential form.

## Audit events

Written to the existing `audit_logs` table, using its existing columns.

| `Action` | `TargetType` | `TargetId` | Recorded |
| --- | --- | --- | --- |
| `oidc.authorize.granted` | `Application` | `client_id` | Code issued |
| `oidc.authorize.denied` | `Application` | `client_id` | Error code, in `Description` |
| `oidc.login.succeeded` | `Account` | Account id | Interactive login |
| `oidc.login.failed` | `Account` | Submitted username, normalized | Generic reason only |
| `oidc.code.redeemed` | `Application` | `client_id` | Code record id in `Description` |
| `oidc.code.replayed` | `Application` | `client_id` | What was revoked in response |
| `oidc.refresh.replayed` | `Application` | `client_id` | Family id and how many descendants were revoked |
| `oidc.session.created` | `Account` | Account id | Session id in `Description` |
| `oidc.session.revoked` | `Account` | Account id | Cause: logout, disablement, replay, administrative |
| `oidc.logout` | `Account` | Account id | Session id |
| `oidc.client.updated` | `Application` | `client_id` | Before/after of interactive settings, secrets excluded |

`ClientIp` and `CorrelationId` are populated from the existing accessors. `BeforeSnapshot` and
`AfterSnapshot` are used only for `oidc.client.updated`, and MUST exclude `app_secret_hash`.

`oidc.code.replayed` and `oidc.refresh.replayed` are the events an operator should alert on. A
correct client never produces either.

## Metrics

Prometheus, through the existing exporter. Labels are bounded — no `sub`, no session id, no
`redirect_uri`, nothing unbounded.

| Metric | Type | Labels |
| --- | --- | --- |
| `signacore_oidc_authorize_total` | counter | `client_id`, `result` (`granted` / `denied`) |
| `signacore_oidc_authorize_error_total` | counter | `client_id`, `error` (the closed set of codes) |
| `signacore_oidc_code_redeem_total` | counter | `client_id`, `result` (`success` / `invalid_grant` / `replay`) |
| `signacore_oidc_login_total` | counter | `result` (`success` / `failure` / `lockout`) |
| `signacore_oidc_session_active` | gauge | none |
| `signacore_oidc_userinfo_total` | counter | `result` |
| `signacore_oidc_authorize_duration_seconds` | histogram | none |

`client_id` is a bounded set because clients are pre-registered; it is the one label worth its
cardinality, since "which application is failing" is the first question during an incident.

## Rate limits, collected

| Partition | Limit | Endpoint |
| --- | --- | --- |
| `authorize:{client_id}` | 60 / min | `/oauth2/authorize` |
| `authorize:{client_ip}` | 30 / min | `/oauth2/authorize` |
| `login:{client_ip}` | 20 / min | Login POST |
| `login:{username}` | 10 / min | Login POST, in addition to the existing 5-attempt lockout |
| `token:code:{client_id}` | 120 / min | `/oauth2/token` |
| `token:code:{client_ip}` | 60 / min | `/oauth2/token` |
| `userinfo:{sub}` | 120 / min | `/oauth2/userinfo` |
| `userinfo:{client_ip}` | 240 / min | `/oauth2/userinfo` |
| `logout:{client_ip}` | 60 / min | `/oauth2/logout` |

These are in-process limiters, like the existing ones, and therefore per instance: a two-instance
PostgreSQL deployment allows twice these numbers in aggregate. That is acceptable because the
limiters bound automated abuse rather than enforcing a quota, and because the account lockout — which
*is* shared state — is the defence that must not be per-instance. Cross-instance limiting is
SignaCore's to build if a deployment needs it; philfanzhou/ServiceMantle#92 covers only single-instance
setup and management limiting.

Every rejection is HTTP 429 with the existing problem-details body, and is never expressed as an
OAuth redirect error.

## Requirements on the client

A BFF integrating with this design MUST:

1. Generate `state`, `nonce`, and `code_verifier` from a CSPRNG, at least 128 bits each, per request.
2. Bind `state` and `nonce` to its own session, and reject a callback whose `state` it did not issue.
3. Verify the ID token's signature, `iss`, `aud`, `exp`, and `nonce` — all five.
4. Verify `iss` in the authorization response before redeeming the code.
5. Keep every token server-side. No token reaches the browser.
6. Send its client secret only over TLS to the token endpoint, never in a URL.
7. Derive local authorization from `iss` + `sub` against its own store, not from claims it wishes
   SignaCore had made.

SignaCore cannot enforce 1, 2, 3, 5, or 7. They are stated because the security of the flow depends
on them and a reference client that gets them wrong will be copied.
