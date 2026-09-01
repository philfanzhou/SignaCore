# Interactive OIDC Canonical Semantic Model

**Status: target design.** This document defines future behavior. None of the endpoints, storage,
claims, or Discovery metadata described here exists merely because this document is present.

This is the only normative source for interactive OIDC state transitions, persistence
relationships, external-input rules, sensitive-value flows, and capability activation. Later
protocol documents explain these decisions and link to the row identifiers below; they must not
create another state matrix or change a cell in this one.

The first phase serves pre-registered confidential BFFs with Authorization Code, S256 PKCE, and a
Password identity login. It does not change the existing grants, `/api/auth/*`, claims callback,
shared-audience applications, or `qz_admin_session`. A claims callback is not a redirect URI and no
value is copied between those registrations.

## State vocabulary and fixed values

The state words in this document are deliberately disjoint.

| Term | Normative meaning |
| --- | --- |
| `missing` | Lookup found no row. Missing is an observation, never a persisted status. It causes no revocation or replay side effect. |
| `expired` | The relevant UTC expiry is at or before the operation time. Expiry does not set `consumed_at` or mean revoked. |
| `revoked` | An explicit revocation timestamp and reason were committed. Revocation is not consumption. |
| `consumed` | A successful one-time operation committed `consumed_at`. Consumption is not revocation. |
| `replay` | A request presented a credential whose committed `consumed_at` was already non-null. Replay is an event with audit and response effects, not another value in the consumed field. |
| `live session` | The row exists; `revoked_at` is null; idle and absolute expiries are in the future; the account is active; and, for an application operation, `auth_time + identity_session_max_age` is in the future when that cap exists. |
| `live family` | The interactive family has not been explicitly revoked, its presented member is unconsumed and unrevoked, its token expiry is in the future, its bound session is live, its account and application are active, and its scope remains allowed. |

Boundary comparisons use one captured UTC operation time. An artifact is valid only when
`operation_time < expires_at`; equality is expired. All ordinal comparisons below are
case-sensitive unless the row explicitly names normalization.

| Constant | Value |
| --- | --- |
| Authorization code | 32 CSPRNG bytes, unpadded base64url, 43 characters; SHA-256 digest stored; 60-second lifetime |
| Continuation handle | 32 CSPRNG bytes, unpadded base64url, 43 characters; SHA-256 digest stored; 10-minute lifetime |
| Logout handle | 32 CSPRNG bytes, unpadded base64url, 43 characters; SHA-256 digest stored; 5-minute lifetime |
| Identity session | 30-minute sliding idle lifetime; 12-hour non-sliding absolute lifetime |
| ID token | RS256, 5-minute lifetime |
| Interactive access token | RS256 `typ: at+jwt`, 15-minute lifetime |
| Interactive refresh token | 32 CSPRNG bytes, unpadded base64url, 43 characters; SHA-256 digest stored; no later than 7 days and never usable beyond its identity session |
| Consumed-code retention | 24 hours after code expiry, so replay remains distinguishable from missing |
| Normal scope order | `openid profile offline_access` with absent values omitted |

## Event × artifact × result

These tables are the state-propagation authority. “Unchanged” means no write and no new rejection
condition. “Valid to `exp`” applies only to signature-valid self-contained tokens; downstream
services do not query SignaCore state.

### Identity, configuration, and lifecycle events

| ID | Event | Authorization request / logout request | Identity session | Unredeemed code | Interactive refresh family | Access token / ID token | Next endpoint result and committed writes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `EV-01` | Password login succeeds | Continuation is consumed only in the successful transaction; its request is revalidated first | New row and new cookie id; an existing cookie id is never reused | A new code is created after revalidation | None until code redemption | None | Commit session, handle consumption, code creation, login/audit records together; then redirect with code |
| `EV-02` | Login is cancelled | Continuation is consumed after its current client and redirect URI are revalidated | No session created or changed | None | Unchanged | Unchanged | Safe redirect with `access_denied`, `state`, and `iss`; if client or redirect revalidation fails, local error and no redirect |
| `EV-03` | Continuation is missing, expired, or consumed | No state write | Unchanged | None | Unchanged | Unchanged | Local 400; no redirect, credential check, failed-attempt count, or replay audit |
| `EV-04` | Session idle or absolute expiry is reached | Pending requests remain until their own expiry | Expired, not revoked; refresh and UserInfo never slide idle expiry | Redemption returns `invalid_grant`, does not consume | Next refresh atomically revokes the family with reason `session_expired` and returns `invalid_grant` | Downstream access token and ID token remain valid to `exp`; UserInfo returns `invalid_token` | A later authorize requires login and can create a new session |
| `EV-05` | Application session max-age is reached or reduced below current `auth_time` | Pending authorization is revalidated and requires a new login | Row remains live for other applications | Redemption for that application returns `invalid_grant`, does not consume | Next refresh atomically revokes that application's family with reason `session_max_age` and returns `invalid_grant` | Downstream access token and ID token remain valid to `exp`; UserInfo returns `invalid_token` for that application | No global session revocation and no effect on other applications |
| `EV-06` | Prepared BFF logout handle is used with matching identity cookie | Logout request is consumed | Session is revoked with reason `logout`; cookie is deleted | Codes bound to the session remain unconsumed and fail live-session checks | Every family bound to the session is explicitly revoked | Downstream tokens remain valid to `exp`; UserInfo fails live-session check | Session and family revocations commit under the session lock before redirect/local success |
| `EV-07` | Logout handle is used without a matching usable cookie | Logout request is consumed | No row changed; presented identity cookie is deleted | Unchanged | Unchanged | Unchanged | Same redirect/local success shape as `EV-06`; no session-state oracle |
| `EV-08` | Account is disabled or deleted | Pending authorization fails account revalidation | Every account session is explicitly revoked in the account-state transaction | Redemption returns `invalid_grant`, does not consume | Every account family is explicitly revoked in the same transaction | Downstream tokens remain valid to `exp`; UserInfo returns `invalid_token` | New authorization and login are denied without revealing account existence |
| `EV-09` | Application is deactivated | Pending authorization/logout preparation fails current application lookup | Sessions remain usable for other applications | That application's redemption returns `invalid_grant`, does not consume | That application's families are revoked with the application change | Downstream tokens remain valid to `exp`; UserInfo returns `invalid_token` | New authorization is a local error because no redirect is trusted |
| `EV-10` | `allow_authorization_code` becomes false | Pending authorization fails revalidation | Unchanged | That application's redemption returns `unauthorized_client`, does not consume | Existing families remain usable if refresh remains enabled and their scopes remain allowed | Existing tokens valid to `exp`; UserInfo unchanged | No new authorization; no implicit audience or redirect change |
| `EV-11` | `allow_refresh_token` becomes false | Pending request containing `offline_access` fails `invalid_scope` after safe redirect revalidation | Unchanged | Code containing `offline_access` returns `invalid_grant`, does not consume | All interactive families for the application are revoked in the setting-change transaction | Existing tokens valid to `exp`; UserInfo ignores `offline_access` | New authorization without `offline_access` remains allowed |
| `EV-12` | Redirect URI is removed | Pending request is revalidated: step 2 fails locally with no redirect | Unchanged | Already issued code retains its exact URI binding and remains redeemable during its 60-second life | Unchanged | Unchanged | New authorization for that URI is local 400; removal never causes a redirect to the removed URI |
| `EV-13` | Scope is removed from an allow list | Pending/new request containing it returns `invalid_scope`; never silently narrowed | Unchanged | Code containing it returns `invalid_grant`, does not consume | Next refresh returns `invalid_grant` and revokes the whole family; no scope narrowing | Downstream tokens valid to `exp`; UserInfo optional claims are the intersection of token scope and the current allow list | `openid` remains a mandatory configured scope; disabling refresh removes `offline_access` as in `EV-11` |
| `EV-14` | `/oauth2/revoke` names a refresh token owned by the authenticated application | Unchanged | Unchanged | Unchanged | The named live token is revoked; family and siblings remain unchanged | Existing access/ID tokens valid to `exp` | Syntactically valid request is always 200 and reveals neither existence nor ownership |
| `EV-15` | Administrator revokes one identity session | Unchanged | Named session revoked with reason `administrative` | Bound codes remain unconsumed and fail | Every bound interactive family explicitly revoked in the same transaction | Downstream tokens valid to `exp`; UserInfo fails | Other browser sessions remain live |
| `EV-16` | Signing key rotates | Unchanged | Unchanged | Unchanged | Unchanged | Previously signed tokens valid to `exp`; retired public key remains available for their validation and the 24-hour logout-hint window | New tokens use the new `kid`; no interval has zero validation/JWKS keys |
| `EV-17` | Password login fails for unknown/wrong/disabled/locked account | Continuation remains live for another attempt until its own expiry | No session created or changed | None | Unchanged | Unchanged | One generic local failure; a syntactically valid login attempt enters the existing shared failed-attempt/lockout path without exposing the cause |
| `EV-18` | Caller cancellation is observed | Before commit, the operation rolls back and leaves a one-time request unconsumed | Before commit, no session/revocation/activity write survives | Before commit, no consumption survives | Before commit, no root/child/revocation survives | No token or claims response is exposed before commit | After commit, cancellation cannot undo state; a client retry follows the relevant consumed/replay row exactly like a lost response |

### Consumption, replay, and transaction events

| ID | Event / observed state | Required locks and checks | Code result | Family/session result | Response and audit |
| --- | --- | --- | --- | --- | --- |
| `EV-20` | First valid code redemption without `offline_access` | Begin transaction; lock session row, then code row; check current client, URI, scope, PKCE, session, account, and application | Set `consumed_at`; `refresh_family_id` remains null | No family; session unchanged | Commit code, issuance audit, and any durable issuance metadata before returning tokens |
| `EV-21` | First valid code redemption with `offline_access` | Same order as `EV-20` | Set `consumed_at` and `refresh_family_id` | Create family root bound to code/session/account/application/scope in the same transaction | Return access, ID, and refresh tokens only after commit |
| `EV-22` | Code digest is missing | No lockable code exists; perform bounded failure work | No write | No write | Generic `invalid_grant`; no replay audit |
| `EV-23` | Code is expired, has wrong binding/PKCE, or current state is rejected | Lock session then code when both exist; use one captured time | No consume | No family/session write except state change already owned by another transaction | Generic `invalid_grant`; no replay audit |
| `EV-24` | A committed consumed code is presented again | Lock its session row when it still exists, then lock the code row; `consumed_at` proves replay even when the session is missing | Remains consumed | Revoke linked family when non-null; revoke the session with reason `code_replay` when present; all sibling families become unusable through the session check | Generic `invalid_grant`; one `oidc.code.replayed` audit naming only non-secret ids |
| `EV-25` | Two callers redeem one unconsumed code | Both use the `EV-20` lock order and conditional consumption | Exactly one commits consumed; loser observes consumed after winner commits | Exactly one root family can be created; losing request executes `EV-24` because it presented a now-consumed credential | One success, one `invalid_grant` replay response; no second token set |
| `EV-26` | Signing, persistence, audit, or commit fails during first redemption | Tokens remain request-local; transaction owns all durable writes | Roll back `consumed_at` and family link | Roll back root/member/audit writes | No token leaves SignaCore; `server_error`; a later valid retry can redeem |
| `EV-27` | HTTP delivery fails after a successful redemption commit | No database rollback is possible after commit | Remains consumed | Issued family remains live | Client retry is a replay (`EV-24`); at-most-once issuance is preferred to a second token set |
| `EV-28` | Logout and first code redemption race | Both lock the same session row before code/family writes | Redemption-first commits consumption; logout-first leaves code unconsumed | Redemption-first: logout then revokes session and family. Logout-first: redemption fails live-session check | Exactly those two serial outcomes; logout never creates a replay audit |
| `EV-29` | Interactive refresh rotates successfully | Lock presented token/family and session in one transaction; recheck all live-family predicates | Unchanged | Set parent `consumed_at`; insert exactly one child with same family/session/scope/auth_time | Commit before returning new access, ID, and refresh tokens; nonce is omitted from refreshed ID token |
| `EV-30` | Two callers rotate one interactive refresh token | Atomic conditional consume or equivalent row lock in shared DB | Unchanged | Exactly one child commits; loser sees consumed parent and executes reuse handling | One success; one `invalid_grant`; family descendants are revoked by `EV-31` |
| `EV-31` | A consumed interactive refresh token is presented | Lock family and presented member plus the session when it still exists; consumption proves reuse independently of session state | Unchanged | Revoke every live descendant in that family; session is not revoked | `invalid_grant` plus one `oidc.refresh.replayed` audit with family id/count, never the token |
| `EV-32` | Interactive refresh is missing, expired, explicitly revoked, scope-invalid, or bound state is not live | Check each state separately; do not infer consumption | Unchanged | No reuse handling. Scope removal and session missing/expiry/max-age atomically revoke the family with a specific reason before failure; a missing token, expired member, or already revoked member adds no write | Generic `invalid_grant`; no replay audit and no child |
| `EV-33` | Legacy refresh token is rotated or rejected | Use the existing validation, `is_revoked`, rotation, exchange-trust, and wire behavior | Unchanged | No interactive reuse guarantee; backfilled singleton family metadata must not change behavior | Existing response and audit behavior remain unchanged |

## Artifact × persistence relationship

All times are UTC. Raw codes, handles, client secrets, and tokens never enter persistence. Digest
columns use the existing versioned SHA-256 construction (`sha256:` plus 64 lowercase hexadecimal
characters). Provider migrations are delivered symmetrically for PostgreSQL and SQLite by the later
implementation tasks; this document itself changes neither history.

| ID | Artifact and authority | Persisted relationship and state | Transaction / integrity rule |
| --- | --- | --- | --- |
| `PS-01` | Interactive application policy | Existing application row owns active flag, authorization/refresh flags, confidential type, allowed scopes, session max-age, and per-application audience mode | Enabling code flow requires `PerApplication`, at least one exact redirect URI, and `openid`; existing applications default disabled |
| `PS-02` | Redirect and post-logout URI registrations | Child rows logically reference application and distinguish `redirect` from `post_logout`; normalized only on registration | Unique `(application, kind, uri)`; claims callback is never read or written by this relationship |
| `PS-03` | Authorization request / continuation | Row contains handle digest, client, exact redirect URI, canonical scope, state, nonce, S256 challenge, created/expiry/consumed times | Handle consumption and session/code creation follow `EV-01`; current policy is always reloaded before any redirect |
| `PS-04` | Identity session | Row contains opaque id, account, the Password credential that authenticated it, `auth_time`, `last_seen_at`, idle/absolute expiries, auth method, optional revoked time/reason | Revocation paths lock this row first; successful browser authorization use advances idle expiry when the stored activity is at least one minute stale, never beyond absolute expiry |
| `PS-05` | Authorization code | Row contains code digest, client, account, non-null restrictive `PS-04` session reference, exact redirect URI, canonical scope, nonce, S256 challenge, auth time, created/expiry/consumed times, nullable `refresh_family_id` | Unique digest. The session reference is created together with the table under `PS-23`, so a stored code can never name a session the schema cannot resolve. Family link points to the family root token id and is set only with root creation in `EV-21`; no-refresh success commits null |
| `PS-06` | Interactive refresh family | The root refresh-token row has `family_id = id` and `parent_id = null`; descendants carry the root id and their immediate parent id. Every member also carries account, application, session, canonical scope, original auth time, digest, issued/expiry/consumed state, and explicit revocation state | Parent and family references cannot cross account/application/session/scope. One child per consumed parent. Code points to root, so two codes from one session remain distinguishable families |
| `PS-07` | Legacy refresh rows | Existing rows are backfilled as singleton roots (`family_id = id`, `parent_id = null`) while current `is_revoked`, bindings, digest, and wire behavior remain authoritative | Null identity session/scope distinguishes non-interactive rows. Existing rotations and cross-application minting do not gain interactive replay semantics |
| `PS-08` | Logout request | Row contains logout-handle digest, authenticated client, account, session id, optional verified post-logout URI, optional state, created/expiry/consumed times | The validated ID token is not stored. Preparation creates the row; browser use atomically consumes it and executes `EV-06` or `EV-07` |
| `PS-09` | Access and ID tokens | No token row. Claims bind issuer, subject, client/audience, session, scope, times, and signing `kid` | Token bytes are built inside the issuance operation, exposed only after its database commit, and cannot be revoked after issue |
| `PS-10` | Signing key | Existing database key row remains the authority; encrypted private material never leaves SignaCore; public material is published while valid | Rotation activates the replacement and retires the prior signer without removing its still-needed validation key |
| `PS-11` | Audit | Existing audit row stores closed event name, bounded public ids, correlation id, and non-sensitive outcome | When an audit is a promised side effect of a state transaction, its row commits with that state; no raw credential or token is included |
| `PS-12` | ID token schema | Header is exactly `alg: RS256`, current `kid`, and `typ: JWT`. Claims always contain `iss`, stable account-id `sub`, single-string `aud=client_id`, `exp`, `iat`, original session `auth_time`, `sid`, and `amr: [pwd]`. Initial code exchange also contains the exact `nonce`; refresh omits it. `profile` adds the bound Password username as `name` and current account nickname when present. `azp`, `acr`, role, permission, `auth_method`, `client_id`, and callback claims are absent | The initial and refreshed ID token use the same subject/session/authentication facts. Callback output never supplies an ID-token or UserInfo core claim. Serialized length over 8192 ASCII characters fails issuance before commit |
| `PS-13` | Interactive access-token schema | Header is exactly `alg: RS256`, current `kid`, and `typ: at+jwt`. Claims contain existing standard/basic/business claims plus `iss`, `sub`, application `aud`, `exp`, `nbf`, `iat`, unique `jti`, `auth_method`, `client_id`, canonical `scope`, and `sid`. Lifetime is 15 minutes. Existing callback and bootstrap-role enrichment remain available, but cannot replace reserved binding claims | Interactive audience is always the application's AppId. Serialized length over 8192 ASCII characters fails issuance before commit. Existing grants retain their current audience, lifetime, claims, and callback behavior |
| `PS-14` | Code-exchange token response | JSON always contains `access_token`, `token_type: Bearer`, `expires_in: 900`, `id_token`, and canonical `scope`; it contains `refresh_token` only for a committed `offline_access` family | Response is constructed request-locally and released only after `EV-20` or `EV-21` commits |
| `PS-15` | Interactive refresh response | JSON contains a new access token, `token_type: Bearer`, `expires_in: 900`, a new ID token without `nonce`, the unchanged canonical family `scope`, and exactly one new refresh token | Original `auth_time` and `sid` are carried forward; response is released only after `EV-29` commits |
| `PS-16` | UserInfo response | Unsigned JSON always contains stable account-id `sub`. When both token scope and current application policy contain `profile`, it also contains the bound Password username as `name` and current non-null account nickname as `nickname`. No callback, role, permission, credential-security, phone, email, or application claim is returned | `sub` is identical to the ID-token subject; current account/session/policy reads are not persisted as a UserInfo artifact |
| `PS-17` | Authorization response | Success is 302 to the verified exact redirect URI with query fields `code`, byte-for-byte `state`, and issuer `iss`. Safe protocol errors use `error`, closed-set English `error_description`, `state`, and `iss`. Fragment and form-post responses do not exist | No response artifact is stored. Local failures never set `Location`; every response is no-store/no-cache/no-referrer |
| `PS-18` | Identity cookie | Separate scheme and Data Protection purpose; name `__Host-signacore_identity`; protected value contains only the opaque session id; `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain` | New id on every login. Deletion repeats the same path/security attributes. It is never accepted as `qz_admin_session`, and the admin cookie is never accepted by identity endpoints |
| `PS-19` | Login antiforgery cookie | Separate Data Protection purpose; name `__Host-signacore_login_csrf`; `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`; paired with `IN-14` | It authorizes only the login form POST and never establishes or extends identity/admin authority |
| `PS-20` | Redirect-URI canonical form | Registration accepts 1–500 ASCII characters, an absolute URI with authority, HTTPS, no userinfo/fragment/wildcard, and at most ten values of each kind. Development alone also accepts literal `127.0.0.1` or `[::1]` over HTTP; `localhost` is always rejected. Query is allowed. Registration lowercases scheme/host, removes a scheme-default port, changes empty path to `/`, and leaves path case, percent encoding, query, and trailing slash unchanged | Stored/displayed canonical string is the comparison value. Requests are never normalized. The same syntax and comparison apply independently to redirect and post-logout URI sets |
| `PS-21` | Interactive client-policy shape | `allow_authorization_code=false`, `client_type=Confidential`, `allowed_scopes={openid}`, `allow_refresh_token=false`, empty URI sets, and no application max-age are upgrade defaults. Supported scopes are exactly `openid`, `profile`, `offline_access`; `openid` is mandatory; `offline_access` requires refresh enabled. Application max-age is positive and no greater than 12 hours | `Public` is representable only as fail-closed reserved data. Code flow requires `PerApplication`. PKCE S256, query response mode, mandatory state/nonce, and no consent are not configurable |
| `PS-22` | Provider concurrency boundary | PostgreSQL supports multiple SignaCore instances against shared rows and uses database row locks plus conditional writes. SQLite supports the same state machine with one SignaCore instance and one database writer; multi-instance SQLite is unsupported | Both providers must prove double-code redemption and double-refresh rotation outcomes. Each explicit transaction runs inside the provider execution strategy and is safe to retry as a unit; PostgreSQL and SQLite migration shapes are symmetric |
| `PS-23` | Reference introduction phase | Every persisted reference in this table is created by the same provider migration that creates its own column, and that migration runs only after the referenced authority table already exists in both histories. `authorization_codes` is therefore created complete: #50 creates the table with its non-null restrictive `PS-04` session reference and runs after #95. The single named exception is the nullable `authorization_codes.refresh_family_id` column, created by #50 without a reference because no family root shape exists yet and added as a restrictive reference by #97 after its backfill | No history state exists in which a stored artifact can name an authority the schema cannot resolve, so no domain-only substitute for a missing reference is ever written. PostgreSQL and SQLite carry the same one-migration shape and the same `Down` boundary: a reference introduced with its table is removed only by dropping that table, and the one deferred reference is removed by the migration that added it |

Cleanup removes expired continuation/logout requests, expired unconsumed codes after the retention
window, consumed codes after the same window, and sessions after their retention policy. Cleanup must
not turn a still-retained consumed code into `missing` before its 24-hour replay window ends. Family
cleanup must preserve referential integrity from retained codes and descendants. Session rows remain
while any retained code, logout request, or interactive family references them; cleanup never uses a
cascade that erases evidence or silently changes a child artifact's state. The restrictive
code-to-session reference of `PS-23` makes that retention rule fail closed in the database rather
than only in cleanup logic, so a retained consumed code keeps a resolvable session row. Replay
handling in `EV-24` must still prove replay from `consumed_at` alone and must not require that read.

## Endpoint × external input

Form and query decoding is strict UTF-8 and happens once. A supported or explicitly rejected
parameter occurring more than once is `invalid_request` before its value is read, even when
duplicates match. Structural rejection
never increments the password failed-attempt counter. Fields marked secret are excluded from logs,
audit, metrics, exception text, tracing tags, and error bodies.

### Authorization and identity login

| ID | Endpoint / field | Encoding, length, normalization, comparison, expiry | Sensitivity | Failure result |
| --- | --- | --- | --- | --- |
| `IN-01` | `GET /oauth2/authorize`: `response_type` | Required ASCII; exactly `code`; no normalization | Public | After client/URI trust: redirect `unsupported_response_type` |
| `IN-02` | `client_id` | Required 1–100 UTF-16 code units before and after NFC + invariant-uppercase lookup normalization | Public identifier | Unknown, inactive, malformed, or non-interactive: local 400, no redirect |
| `IN-03` | `redirect_uri` | Required 1–500 ASCII characters; no request normalization; exact ordinal match to a registered normalized string | Sensitive configuration | Missing/unmatched: local 400, no redirect |
| `IN-04` | `scope` | Required 1–200 ASCII characters; U+0020-delimited unique members from `openid`, `profile`, `offline_access`; must include `openid`; stored in fixed normal order | Public policy | Safe redirect `invalid_scope`; never silently narrowed |
| `IN-05` | `state` | Required 22–128 ASCII `[A-Za-z0-9._~-]`; opaque; no normalization; echoed byte-for-byte | Correlation-sensitive | Safe redirect `invalid_request` |
| `IN-06` | `nonce` | Required 22–128 ASCII `[A-Za-z0-9._~-]`; opaque; no normalization; exact copy into the first ID token only | Correlation-sensitive | Safe redirect `invalid_request` |
| `IN-07` | `code_challenge` | Required exactly 43 ASCII `[A-Za-z0-9_-]`, no padding; exact stored comparison | Credential-derived secret | Safe redirect `invalid_request`; `.` and `~` are rejected |
| `IN-08` | `code_challenge_method` | Required ASCII; exactly `S256` | Public | Safe redirect `invalid_request` |
| `IN-09` | Rejected authorization fields | Any `prompt`, `max_age`, `acr_values`, or `response_mode` is `invalid_request`; `request`, `request_uri`, and `registration` use their named unsupported errors; other unknown fields are ignored | Treat values as sensitive input | Safe redirect only after `IN-02` and `IN-03` succeed |
| `IN-10` | `GET /oauth2/login`: `login_handle` | Sole supported query field; required exactly 43 ASCII `[A-Za-z0-9_-]`; digest lookup; expires in 10 minutes; no normalization | Secret handle | Missing/malformed/missing row/expired/consumed: local 400, no redirect |
| `IN-11` | `POST /oauth2/login`: `login_handle` | Same as `IN-10`; exact submitted bytes identify the server-side request | Secret handle | Local 400; no credential validation or failed-attempt write |
| `IN-12` | Login `username` | Required only for `action=login`; decoded UTF-8; 1–100 UTF-16 code units both before and after NFC + invariant-uppercase normalization; never trimmed; normalized ordinal lookup. Ignored without lookup for `action=cancel` | Personal identifier | Malformed/over-limit on login: local 400. Valid unknown value shares the generic credential failure |
| `IN-13` | Login `password` | Required only for `action=login`; opaque decoded UTF-8; 1–1024 UTF-16 code units; never trimmed, normalized, echoed, or compared outside the password hasher. Ignored without validation for `action=cancel` | Secret credential | Malformed/over-limit on login: local 400. Empty/wrong shares the generic credential failure |
| `IN-14` | `__RequestVerificationToken` | Required 1–2048 ASCII characters, bound to a separate `__Host-` cookie; exact cryptographic validation; request lifetime only | Secret CSRF value | Local 400; no credential validation or failed-attempt write |
| `IN-15` | Login `action` | Required ASCII; exactly `login` or `cancel` | Public | Local 400. Cancel executes `EV-02` without validating username/password |

`POST /oauth2/login` accepts only `application/x-www-form-urlencoded`, a body of at most 16 KiB,
and only the five named fields. The handle, action, and antiforgery value are checked before fields
conditional on the action.

Authorization first checks `client_id` and `redirect_uri` cardinality before reading them, resolves
the current client, and establishes the exact trusted redirect URI. It then checks every remaining
supported/rejected field's cardinality before reading that field, followed by response type,
rejected fields, state, scope, nonce, S256 fields, live session, and active account. A duplicate
client or redirect URI is always a local 400. Redirection is forbidden until the current client and
exact redirect URI have both succeeded. Login success or cancellation consumes the handle only
after rerunning the same current client, redirect, scope, and account decisions.

### Token and UserInfo

`POST /oauth2/token` accepts only `application/x-www-form-urlencoded` with a body of at most 16 KiB.
The authorization-code and interactive-refresh branches ignore unknown form fields, as OAuth
requires, and never pass them into another grant's field mapping.

| ID | Endpoint / field | Encoding, length, normalization, comparison, expiry | Sensitivity | Failure result |
| --- | --- | --- | --- | --- |
| `IN-20` | `/oauth2/token` client authentication | Exactly one of `client_secret_basic` or `client_secret_post`; client id 1–100, secret 1–256 UTF-16 code units; no simultaneous methods; existing normalized client lookup and password-hash verification | Secret credential / header | `invalid_client`, HTTP 401, `WWW-Authenticate: Basic`; no body echoes |
| `IN-21` | `grant_type=authorization_code` | Required ASCII exact value; form encoded | Public | Unknown: `unsupported_grant_type`; disabled client: `unauthorized_client` |
| `IN-22` | `code` | Required exactly 43 ASCII `[A-Za-z0-9_-]`; SHA-256 digest lookup; 60-second record lifetime | Secret credential | Malformed: `invalid_request`; all lookup/state/binding failures: generic `invalid_grant` |
| `IN-23` | Token `redirect_uri` | Required 1–500 ASCII; no normalization; ordinal equality to the code snapshot, not a fresh URI-set match | Sensitive configuration | Malformed: `invalid_request`; mismatch: generic `invalid_grant` |
| `IN-24` | `code_verifier` | Required 43–128 ASCII `[A-Za-z0-9._~-]`; compute `BASE64URL(SHA256(ASCII(value)))`; constant-time compare to challenge | Secret credential | Malformed: `invalid_request`; mismatch: generic `invalid_grant` |
| `IN-25` | Code-token `scope` | Must be absent; authorization snapshot is authoritative | Treat supplied value as sensitive input | `invalid_request` |
| `IN-26` | `grant_type=refresh_token`: `refresh_token` | Required 1–256 ASCII; digest lookup. New interactive values are exactly 43 unpadded-base64url characters; legacy accepted shapes remain compatible | Secret token | Malformed: `invalid_request`; all token/family/binding failures: generic `invalid_grant` |
| `IN-27` | Refresh `scope` | Must be absent for this phase; family snapshot is authoritative and never silently narrowed | Treat supplied value as sensitive input | `invalid_request` |
| `IN-28` | `GET /oauth2/userinfo`: `Authorization` | Exactly one `Bearer` credential; scheme comparison is ASCII case-insensitive; compact access JWT is at most 8192 ASCII characters; no query, form, cookie, ID-token, refresh-token, or client-secret alternative | Secret token/header | Missing header: 401 with bare `Bearer`. Malformed/multiple header or alternate token carrier: 400 `invalid_request` |
| `IN-29` | UserInfo token and authority | Validate `typ: at+jwt`, signature, issuer, time, per-application audience/client, account, application, and live session. Token must contain `openid`, `sid`, and canonical `scope`; current optional claims use token-scope/current-allow-list intersection | Claims / personal data | Bad `typ`, cryptographic/time/binding failure, or rejected current state: 401 `invalid_token`. A signature-valid access token missing interactive claims or `openid`: 403 `insufficient_scope`. Valid result uses `PS-16` |

Successful token and UserInfo responses use `Cache-Control: no-store` and `Pragma: no-cache`.
Token failures after code lookup share one fixed English `invalid_grant` description and do not
reveal whether a code was missing, expired, consumed, misbound, or failed PKCE.

### Logout without an ID token in the browser

`POST /oauth2/logout/requests` accepts only `application/x-www-form-urlencoded` with a body of at
most 16 KiB; unknown fields are rejected. `GET /oauth2/logout` accepts no request body and no query
field other than `logout_handle`.

| ID | Endpoint / field | Encoding, length, normalization, comparison, expiry | Sensitivity | Failure result |
| --- | --- | --- | --- | --- |
| `IN-30` | `POST /oauth2/logout/requests` client authentication | Same exclusive confidential-client authentication as `IN-20` | Secret credential / header | `invalid_client`, HTTP 401; no logout row |
| `IN-31` | `id_token_hint` | Required compact JWS, 1–8192 ASCII chars; validate RS256 signature, issuer, authenticated-client audience, `sub`, `sid`, and `iat` no older than 24 hours; ignore `exp` only for logout preparation | Secret token | Generic local JSON `invalid_request`, HTTP 400; token never stored |
| `IN-32` | `post_logout_redirect_uri` | Optional 1–500 ASCII; no request normalization; exact ordinal match to that client's registered post-logout set | Sensitive configuration | `invalid_request`, HTTP 400; no row and no redirect |
| `IN-33` | Logout `state` | Optional 22–128 ASCII `[A-Za-z0-9._~-]`; opaque; stored and later echoed byte-for-byte | Correlation-sensitive | `invalid_request`, HTTP 400 |
| `IN-34` | Preparation response | JSON contains one relative or same-origin `logout_uri` whose only query value is a new `logout_handle`; `Cache-Control: no-store` | Secret handle | Internal failure: 500; no partial row/handle exposure |
| `IN-35` | `GET /oauth2/logout`: `logout_handle` | Sole supported query field; required exactly 43 ASCII `[A-Za-z0-9_-]`; digest lookup; expires in 5 minutes; single-use | Secret handle in browser URL | Missing/malformed/missing row/expired/consumed: local 400, no redirect |
| `IN-36` | Identity cookie at logout | Protected opaque session id; exact equality to stored logout request `sid`, and stored session account must equal request `sub` | Secret cookie/session | Missing/unusable/mismatch: `EV-07`; impossible same-id/different-account corruption: local 400 and no state write |

`id_token_hint` travels only from the BFF server to the authenticated preparation endpoint. The BFF
redirects the browser to the returned opaque handle URL; neither the browser, its history, a proxy
request line, nor SignaCore access logs receive an ID token. Logout-handle query values must still be
redacted because their disclosure can disrupt a pending logout.

This prepared transport is intentionally not wire-compatible with a standard client navigating
directly to an RP-Initiated Logout `end_session_endpoint`: such a client would put
`id_token_hint` in the browser request. The first phase therefore keeps `end_session_endpoint`
absent from Discovery instead of claiming interoperability it does not provide.

## Sensitive value × trust boundary and data flow

“No” means the value must not cross that boundary in plaintext. Digests and bounded non-secret ids
are named explicitly where allowed.

| ID | Value | Browser | Confidential BFF | SignaCore process | Database | Logs, audit, metrics, traces | Downstream resource service |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `DF-01` | Password | Login form and TLS request only; never browser storage | No | Request-local validation only | Existing password hash only | Never | No |
| `DF-02` | Client secret / client `Authorization` header | No | Server-side store and TLS back channel | Request-local authentication | Existing password hash only | Never; header redacted | No |
| `DF-03` | Authorization code | Authorization response URL and BFF callback only | Request-local until token exchange | Generated/validated request-locally | Versioned digest and public record id only | Never plaintext; callback query redacted | No |
| `DF-04` | PKCE verifier / challenge | Challenge appears in the authorize URL; verifier never reaches the browser | Verifier and derived challenge stay in server-side request state | Request-local; challenge snapshot | Challenge is stored with request/code; verifier is never stored | Neither value logged | No |
| `DF-05` | Continuation handle | Login URL/form only | No | Generated and digested | Digest only | Query/form value redacted | No |
| `DF-06` | Identity cookie and session id | Protected cookie only | No | Cookie unprotected and row id used | Public row id and state; never cookie envelope | Cookie never; bounded session id allowed only in audit description | No |
| `DF-07` | Access token | No; BFF's own browser session is unrelated | Server-side token store and Bearer use | Issued request-locally; accepted at UserInfo | No token row | Never; authorization header redacted | Bearer request and validation memory only |
| `DF-08` | ID token | No, including logout | Server-side validation/store and logout preparation only | Issued or validated request-locally | No | Never | No |
| `DF-09` | Refresh token | No | Server-side token store and TLS token request | Generated/validated request-locally | Versioned digest only | Never | No |
| `DF-10` | Logout handle | Logout URL only; no durable browser storage | Receives URI then redirects browser | Generated and digested | Digest plus verified non-token context | Query value redacted | No |
| `DF-11` | `state` / `nonce` | Authorization URL; state returns to callback | Bound to BFF session; nonce used for ID-token validation | Validated and copied as specified | Request/code snapshots; nonce omitted from refreshed ID tokens | No raw values despite not being bearer credentials; use correlation id instead | No |
| `DF-12` | Redirect and post-logout URI | Authorization/logout navigation | Client configuration | Validation and response construction | Registered and request snapshots | May log only a sanitized registered value; never an untrusted raw URI | No |
| `DF-13` | Account/client/code/family record ids | No need to expose | Client id only | Used for joins and audits | Plain bounded identifiers | Allowed where needed; never metric labels except bounded registered client id | `sub` and `client_id` claims as specified |
| `DF-14` | Signing private key / root key | No | No | Private signing operation / key unwrapping only | Existing encrypted private material; root key external | Never | No; only public JWKS material |
| `DF-15` | UserInfo claims | No direct browser response from SignaCore | Server-side response, then BFF decides its own session/profile exposure | Current-account lookup and response | Existing account fields | No complete response or personal values | No unless BFF separately authorizes disclosure |

All browser endpoints set `Referrer-Policy: no-referrer`; all credential or token responses set
`Cache-Control: no-store`. Login pages additionally deny framing. Test fixtures use synthetic values
and failure diagnostics identify the stage by public record ids, never by copying a secret.

## Implementation task × capability activation

Documentation tasks #129–#134 never activate a capability. Runtime routes may exist before
advertisement for integration testing, but public Discovery must not lead a conforming client into
an incomplete flow.

| ID | Implementation task / completed slice | Runtime capability after the slice | Discovery effect |
| --- | --- | --- | --- |
| `AC-01` | #61 interactive policy and redirect persistence | Disabled-by-default configuration exists | None |
| `AC-02` | #64–#66 identity cookie, Password login, and continuation | Browser can establish isolated identity state for internal flow tests | None |
| `AC-03` | #50 code persistence, after #95 identity-session persistence | Codes can be stored and atomically consumed by internal tests, already bound to a resolvable session row (`PS-23`) | None |
| `AC-04` | #93 authorization validation | Requests and safe errors can be validated | None |
| `AC-05` | #94 authorization orchestration | `/oauth2/authorize` can issue a code bound to the session row committed by the same `EV-01` transaction | None; a code alone is not a usable advertised flow |
| `AC-06` | #53 code grant and PKCE redemption | `/oauth2/token` can redeem code for an application access token | None until ID-token issuance closes OIDC core |
| `AC-07` | #54 ID-token issuance and end-to-end core tests, after #96 live-session enforcement; its #95 prerequisite is already required by `AC-03` | Complete confidential-BFF code flow with the database session checks required by redemption | Atomically add `authorization_endpoint`, `response_types_supported: [code]`, `authorization_code`, `S256`, then-supported scopes, and actual client-auth methods; retain the already truthful RS256 algorithm metadata |
| `AC-08` | #55 UserInfo implementation and tests, after #96 live-session enforcement | `/oauth2/userinfo` is usable with all current-state checks | Add `userinfo_endpoint` only now |
| `AC-09` | #67 identity-session persistence/lifecycle and #69 state propagation, of which the #95 storage slice is already required by `AC-03` | Cross-instance session authority and disablement behavior are enforceable | No new metadata; prerequisites must be complete before dependent capability is considered production-ready |
| `AC-10` | #68 logout preparation, browser completion, and tests | Token-safe prepared logout is usable by the first-party BFF contract | No standard `end_session_endpoint`; it stays absent because the browser handle endpoint does not accept the standard request shape |
| `AC-11` | #97 family persistence | Interactive family shape exists but reuse handling is not active | Do not advertise `offline_access` |
| `AC-12` | #98 atomic rotation/reuse handling plus required session lifecycle | Interactive offline access is end-to-end usable | Add `offline_access` to `scopes_supported` only now; existing advertised `refresh_token` grant remains truthful throughout |
| `AC-13` | #71 operational protections and later attack-matrix tasks | Rate limits, audit, metrics, and sensitive canaries meet production gate | Metadata unchanged; release activation waits for required protections |
| `AC-14` | #129–#134 design chain | English target contract is complete | Current runtime metadata remains byte-for-byte unchanged |

If an implementation is deployed without all prerequisites named in its row, the associated setting
must remain disabled and the metadata absent. `/.well-known/openid-configuration` and
`/.well-known/oauth-authorization-server` continue to describe the same actually available
capabilities.

## End-to-end semantic scenarios

Each scenario was evaluated across input, persisted relationships, transaction order, response, and
sensitive-data boundaries. These are expected outcomes, not claims about current runtime tests.

| ID | Scenario and ordering | Unique result |
| --- | --- | --- |
| `SC-01` | A new browser submits a valid authorize request, then valid Password credentials, then the BFF redeems the code | Request is stored by digest; login revalidates current policy; one new session and code commit; one redemption consumes code and returns ID/access tokens plus an optional linked refresh root; no secret is logged |
| `SC-02` | Application is deactivated while the login form is open | Login credentials may validate, but current client revalidation fails; handle is not used to redirect to an untrusted destination, no code/token is issued, and the local result reveals no credential detail |
| `SC-03` | Redirect URI is removed while the login form is open | Step-2 revalidation fails locally with no `Location`; no session/code issuance transaction commits for that continuation |
| `SC-04` | A requested scope is removed while the login form is open | Current client/URI remain trusted, so response safely redirects `invalid_scope` with original state/issuer; no silent narrowing and no code |
| `SC-05` | Logout obtains the session lock before an unredeemed code request | Logout consumes its handle and commits session/family revocation; code redemption then returns generic `invalid_grant`, leaves code unconsumed, and emits no replay audit |
| `SC-06` | Code redemption obtains the session lock before logout | Redemption commits one token set and optional family; logout then revokes the session and every bound family; access/ID tokens remain valid only to `exp`, and UserInfo fails immediately |
| `SC-07` | Two independently issued codes for one session/application both request offline access | Each code creates and records its own root family id. Redeeming or replaying one can locate that exact family; the two are never inferred from account/client/session/scope |
| `SC-08` | A successfully consumed code with a linked family is replayed | Request returns generic `invalid_grant`; exact linked family and session are revoked; sibling families become unusable through session state; one replay audit contains only ids |
| `SC-09` | A successfully consumed code that issued no refresh token is replayed | `refresh_family_id` is null; session is still revoked, no arbitrary family is selected, and one replay audit records that no family existed |
| `SC-10` | Session reaches idle or absolute expiry before code redemption, refresh, and UserInfo | Code stays unconsumed and returns `invalid_grant`; refresh returns `invalid_grant` without reuse audit/child; UserInfo returns `invalid_token`; downstream access token remains valid to `exp`; next authorize requires login |
| `SC-11` | `profile` is removed after tokens/family were issued | New/pending authorization rejects `invalid_scope`; old code cannot redeem; next family refresh fails and revokes family without narrowing; downstream access token remains valid to `exp`; UserInfo returns only claims still permitted by current policy |
| `SC-12` | Application is disabled after code issue and before redemption/refresh/UserInfo | Code is not consumed; no tokens are issued; family refresh and UserInfo fail; application families are revoked by the state-change transaction; other applications and the identity session remain usable |
| `SC-13` | Two instances redeem the same code concurrently | Shared row/session locking and conditional consumption produce exactly one commit. The loser observes committed consumption, executes code-replay handling, and never produces a second token set |
| `SC-14` | Two instances rotate the same interactive refresh token concurrently | Exactly one child commits. The other observes a consumed parent, revokes live descendants in the family, returns `invalid_grant`, and emits reuse audit without exposing a token |
| `SC-15` | BFF initiates logout | ID token moves BFF-to-SignaCore only over authenticated TLS; database stores verified ids/URI/state but no token; browser receives only a one-time logout handle; matching cookie revokes, while mismatch has the same successful external shape and no revocation |
| `SC-16` | Signing fails before issuance commit | Code consumption, family root/link, and audit roll back; no token bytes leave the process; later valid retry may succeed and is not classified as replay |
| `SC-17` | Signing key rotates while issued tokens and a logout hint still need validation | New issues use the new key; old public key remains available through every token `exp` and the 24-hour logout-hint acceptance window; no session/family/code state changes |
| `SC-18` | A continuation, code, refresh token, or logout handle lookup is missing | Each endpoint returns its generic local/protocol error; no consumed/revoked state is invented, no family/session is guessed, and no replay audit occurs |
| `SC-19` | Login POST has invalid CSRF versus valid but wrong credentials | Invalid CSRF is local 400 with no credential lookup or failed-attempt write. Wrong credentials keep the continuation unconsumed, record the existing bounded failure/lockout state, and return the same local message as unknown, disabled, or locked credentials |
| `SC-20` | Cancellation arrives during login, code issuance, refresh rotation, or logout | If observed before commit, every state write and generated response artifact is discarded and the one-time input keeps its prior state. If observed after commit, committed consumption/revocation remains authoritative and any retry follows normal replay/idempotency behavior |

## Guarantees and caller responsibilities

The model guarantees a single implementable result for the rows above and enough persisted
association to execute every promised state change. It does not make current SignaCore an OpenID
Provider, provide token introspection, revoke self-contained access tokens, implement public clients,
MFA, consent, dynamic registration, front-channel logout, or back-channel logout.

The BFF must generate and bind high-entropy `state`, `nonce`, and `code_verifier`; validate the
authorization response issuer; validate ID-token signature, issuer, audience, lifetime, and nonce;
keep every token server-side; and derive its own authorization from issuer plus subject. Downstream
resource services must validate access-token signature, issuer, audience, and lifetime and must
accept that account, application, session, or scope changes do not revoke a self-contained access
token before `exp`.
