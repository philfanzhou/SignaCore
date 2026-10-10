# Authorization Code Redemption

**Status: target design.** Read the [directory boundary](./README.md) and the
[canonical model](./CanonicalSemanticModel.md) first.

`POST /oauth2/token` has an `authorization_code` branch for pre-registered confidential BFFs
and a Public client branch. Public requests use exactly one form `client_id`, no
`client_secret` field, and no `Authorization` header. The identifier is a binding value, not a
credential. An administrator may explicitly enable Public Code + S256 authorization; Discovery
advertises `none` for the token endpoint only.
The branch redeems one short-lived code for the response in `PS-14`; it does not reuse a browser
identity cookie as client authentication and does not add this grant to `/api/auth/token`.

New Public Code access tokens expire 300 seconds after the captured issuance second, while
Confidential interactive access tokens remain at 900 seconds. `expires_in` is derived from the
same expiry used in the JWT. Public interactive refresh uses the same constructor after explicit
refresh opt-in and a committed Code exchange. Tokens issued before this change keep their
original `exp`, and downstream services must validate the exact issuer, audience, signature, and
expiry.

## Public Origin CORS

The host excludes all `/oauth2` paths from AdminWeb CORS. A token preflight admits only `POST`
with `Content-Type` from the current union of active Public application Origins. It cannot bind
an application because a preflight has no token form. An actual response to a single
`grant_type=authorization_code` or `grant_type=refresh_token` request carries the exact Origin
only when the bounded form parsed, client authentication has selected an active Public
application, that Origin is still registered to it, and the request was not cancelled before the
response started. Code and refresh share this one condition: a successful rotation and a protocol
error after client authentication, such as reuse or a disabled refresh policy returning
`invalid_grant`, are readable by that Origin; failures before client authentication selects the
application (`invalid_request`, `invalid_client`, `unauthorized_client`) and Confidential clients
are not. No wildcard, credentials header, or preflight cache lifetime is sent; `Vary` covers Origin
and the preflight method and headers. Authorization, revoke, and logout do not gain Public CORS.
CORS limits browser response access, not token issuance, rotation, or non-browser callers; a
rejected Origin does not roll back a committed rotation. Clients must still use PKCE and avoid
cookies.

## Request boundary

The endpoint accepts one bounded `application/x-www-form-urlencoded` body as specified before
`IN-20`. Unknown fields are ignored by this branch, but supported fields and client-authentication
methods still have exact cardinality. The canonical field index is:

| Input | Canonical owner |
| --- | --- |
| `client_secret_basic` or `client_secret_post` | `IN-20` |
| `grant_type=authorization_code` | `IN-21` |
| `code` | `IN-22` |
| `redirect_uri` | `IN-23` |
| `code_verifier` | `IN-24` |
| Rejected `scope` | `IN-25` |

Exactly one client-authentication method is allowed. Basic credentials and form credentials cannot
be combined, even when their values match. Authentication failure is `invalid_client` with HTTP 401
and a Basic challenge. A valid confidential client that is not allowed to use code flow receives
`unauthorized_client`; malformed branch fields receive `invalid_request`. No response echoes an
input credential or a raw form value.

The Public `none` method applies to `authorization_code` and a complete, correctly bound
interactive refresh family. A current active Public row must
have an empty secret hash, code permission, and `PerApplication` audience. The code remains bound
to that row, its exact redirect URI, and the S256 verifier. A Public code carrying `offline_access`
creates one root and code-to-family link in the redemption transaction only while current policy
still allows it. The root deadline is the earliest of seven days, the session's absolute expiry,
and the original authentication time plus the application's maximum age. A code without that scope
creates no root. Revoke continues to require a confidential client. A Public refresh presentation
must contain exactly one each of `grant_type=refresh_token`, `client_id`, and `refresh_token`, with
no Authorization header, `client_secret`, or additional form fields. The identifier selects the
application; only the digest-matched family, exact application binding, current Public policy,
account, and session authorize rotation. Missing and legacy tokens never enter the legacy grant.
A Public family's current policy must explicitly allow refresh, set a 1–43200-second identity
session maximum age, and still allow its `offline_access` snapshot. Existing manually seeded
families without these settings are rejected. A consumed, correctly bound member still triggers
reuse disposal before the current policy check. Origin and Cookie do not authenticate a refresh bearer.
A code request without any client identifier or credentials is `400 invalid_request`; the
confidential authentication failures of other grants remain `401 invalid_client`.

The request `redirect_uri` is compared ordinally with the exact snapshot on the code, without
normalization. For an unconsumed code, a separate check applies the `PS-20` structural rules to that
snapshot and requires its complete URI to remain exactly registered to the current active client.
Under `EV-12`, removing that registration rejects even an unexpired code with generic
`invalid_grant`, without consuming it or issuing tokens. A correctly authenticated and statically
bound consumed code follows `EV-24` before the structural/current-registration check; registration
drift cannot bypass replay disposal. The `scope` parameter is rejected because the authorization
snapshot is authoritative and cannot be narrowed during redemption.

## Code authority and persistence

`PS-05` is the complete authorization-code relationship. This implementation-facing projection
explains why every persisted value exists without defining a second schema:

| Concern | Canonical relationship |
| --- | --- |
| Credential lookup | Only a versioned SHA-256 digest and a public record id are stored; the raw 43-character code is returned once |
| Static binding | Client, account, exact redirect URI, canonical scope, nonce, S256 challenge, and authentication facts are snapshots |
| Live authority | The non-null restrictive session reference reaches the current session/account state; current application policy is loaded separately |
| Lifecycle | Created, expiry, and consumed times keep `expired` and `consumed` distinct |
| Replay output | Nullable `refresh_family_id` points to the exact root created by this code's first redemption |

The family link is load-bearing. With `offline_access`, root creation and the code-to-root link commit
together under `EV-21`. Without it, `EV-20` commits a null link. Replay handling never searches by
account, client, session, or scope, because two independent codes can share all four and still create
different families (`SC-07`–`SC-09`). The family shape and rotation behavior belong to the later
refresh-family document.

`PS-23` fixes when that session reference exists: #50 creates the authorization-code table complete,
after #95 has created the session authority, so no history state stores a code whose session cannot
be resolved and no domain-only substitute for the reference is ever written. The nullable
`refresh_family_id` column is the one reference #50 creates without a constraint, because the family
root it names does not exist until #97.

Raw code and verifier handling follows `DF-03` and `DF-04`. The verifier is never persisted, while
the S256 challenge is a code snapshot. A valid verifier is transformed exactly as `IN-24` specifies
and compared to that challenge in constant time. Missing rows cause no invented state, family guess,
or replay audit (`SC-18`).

Expired code rows remain available through the retention window; consumed rows remain for 24 hours
after expiry so an authenticated, correctly bound replay stays distinguishable from a missing code.
Cleanup obeys the referential-integrity paragraph after `PS-22` and cannot erase a linked root,
session, or replay fact prematurely.

## Transaction and validation order

A digest lookup may first discover the code's session id without locking the code. The issuance
transaction then locks the session row before the code row and re-reads every authoritative value.
This two-stage lookup preserves the global lock order: code redemption, logout, and administrative
revocation never take code/family state before the session authority.

Before callback HTTP or key refresh, unconsumed-code prechecks reject unusable session/account/
application state, removed registration, structurally invalid stored URI, and disallowed current
policy. These reads avoid unnecessary external work but are not authoritative; the issuance
transaction repeats current-state checks under its locks. A correctly bound consumed code enters
the replay transaction before these prechecks.

Within that boundary, the implementation distinguishes these decisions:

1. Authenticate the client, select the code branch, validate cardinality/shape, and load the current
   application capability before treating any code as usable.
2. Digest-lookup the code. A missing row follows `EV-22`.
3. Verify the authenticated client, exact redirect snapshot, and S256 proof. A wrong binding or
   proof follows `EV-23`; it cannot trigger replay side effects.
4. Lock the named session, then the code, and repeat the static checks against the locked row.
5. If the correctly bound code is already consumed, execute `EV-24`. Committed consumption proves
   replay from `consumed_at` alone and must not depend on reading the session row; an
   expired-but-retained consumed code is still a replay. The restrictive reference and the no-cascade
   retention rule mean that row is normally still present, so this independence is a fail-closed
   requirement rather than a routine branch.
6. For an unconsumed code, recheck the stored URI's `PS-20` structure and complete ordinal
   registration against the current active application. Use one captured UTC time to check code
   expiry, current scope/refresh policy, live session including application max-age, active account,
   and active application. `EV-04`, `EV-05`, `EV-08`, `EV-09`, `EV-11`, `EV-12`, and `EV-13`
   provide the state-specific result; rejection follows `EV-23` and leaves `consumed_at` null.
7. Build the token bytes request-locally, perform the conditional consumption, create and link an
   optional family root, and commit every promised issuance/audit write as `EV-20` or `EV-21`.
8. Release the response only after commit. Signing, persistence, audit, cancellation before commit,
   or commit failure follows `EV-18`/`EV-26`: all writes roll back and no token bytes leave SignaCore.

The successful conditional write is still required after row locking. It protects the invariant
against implementation changes and provider behavior: `consumed_at` changes only when it is null and
the code is unexpired at the captured operation time. Every explicit transaction runs inside the
provider execution strategy and is retry-safe as a unit (`PS-22`).

## Failure and replay results

| Observed result | Canonical outcome |
| --- | --- |
| Missing or failed client authentication, including a deactivated application | `IN-20`: 401 `invalid_client`; no code lookup side effect |
| Unknown grant or disabled code capability | `IN-21`/`EV-10`: `unsupported_grant_type` or `unauthorized_client`; code remains unconsumed |
| Malformed code fields or present `scope` | `IN-22`–`IN-25`: `invalid_request`; no code state write |
| Missing code | `EV-22`: generic `invalid_grant`; no replay audit |
| Unconsumed expired, misbound, bad-PKCE, or current-state-rejected code | `EV-23`: generic `invalid_grant`; no consumption, family, session change, or replay audit |
| Correctly bound consumed code | `EV-24`: generic `invalid_grant`; revoke the exact linked family when present and the session when present; one id-only replay audit |
| Signing, persistence, audit, or commit failure | `EV-26`: 500 `server_error`; complete rollback and no token response |
| HTTP delivery lost after commit | `EV-27`: committed state remains authoritative; retry follows replay behavior |

Every code-rejection result after lookup uses the same fixed English `invalid_grant` description and
does not disclose which lookup, binding, PKCE, time, or current-state check failed. `EV-26` remains a
distinct internal `server_error`. Error responses and success responses are no-store/no-cache; code,
verifier, client secret, tokens, raw redirect URI, nonce, and scope input are excluded from logs,
audit text, metrics, traces, and exceptions.

Replay directly revokes only the nullable family named by the code. It never guesses or directly
marks a sibling family. Revoking the identity session makes every sibling family unusable through
its live-session predicate, which is the distinct session-wide effect required by `EV-24`.

## Concurrency proofs

`PS-22` requires the same state machine on both providers. PostgreSQL permits multiple SignaCore
instances over shared rows. SQLite permits one SignaCore instance and one writer; multi-instance
SQLite is unsupported.

Two valid callers redeeming one code take the same session-then-code lock order. Exactly one executes
`EV-20` or `EV-21`; the loser observes committed consumption and executes `EV-24` (`EV-25`, `SC-13`).
If logout locks the session first, redemption rejects the live-session check without consuming or
auditing replay (`SC-05`). If redemption locks first, one token set commits and logout subsequently
revokes the session and any created family (`SC-06`); these are the only `EV-28` outcomes. Signing
failure and caller cancellation use `SC-16` and `SC-20`; neither can expose a token before the
matching durable state commits.

A Public redemption, and a Confidential redemption whose code carries `offline_access`, read the
application under a shared row lock after the session and code. The administrative deactivation
(`EV-09`) and refresh-capability-off (`EV-11`) transactions take an exclusive lock on the same row
before they revoke the application's families and take no session or code lock. On PostgreSQL, a
change that locks first is observed by the redemption, which then rejects without a root; a
redemption that locks first commits its root before the change proceeds, and the change's
revocation statement revokes that root. The shared lock does not serialize concurrent redemptions
or rotations of one application with each other. A Confidential code without `offline_access`
writes no family and keeps a plain read for that later family-policy lookup; its current URI-trust
check still share-locks the application and registration rows. SQLite reaches the same outcomes
through its single writer.

Provider contract tests run `SC-13` against PostgreSQL across shared-database instances and against
SQLite as concurrent requests to its single instance. The same suites force both serial outcomes in
`SC-05`/`SC-06`; neither provider may consume a logout-first code or manufacture a replay audit.

## Compatibility and activation

Current Password, SMS, LDAP, WeChat, legacy Refresh, cross-application exchange, callback enrichment,
audience selection, `/api/auth/*`, and their response/audit behavior do not change. Existing grants
continue rejecting scope at the standards endpoint and return neither `id_token` nor `scope`.
Interactive refresh remains a separately identified future family path and does not reinterpret a
legacy refresh row.

#50 activates storage only (`AC-03`) and runs after #95 so its table carries the session reference
from creation (`PS-23`); #53 activated internal code redemption (`AC-06`); #54 completed the core
by adding the ID token to the response and publishing the interactive metadata (`AC-07`). The
redemption response now carries `access_token`, `token_type`, `expires_in`, `scope`, and
`id_token`, plus a one-shot plaintext `refresh_token` when the code's approved scope carries
`offline_access`: the redemption slice of #294 delivers `EV-21`, creating and linking the family
root in the same redemption transaction, and the rotation slice (#98) delivers the atomic
`refresh_token` grant: one transaction consumes the presented member, inserts exactly one child,
and returns the `PS-15` response — a new access token, a nonce-free ID token, the unchanged
canonical scope, and exactly one new refresh token — after the commit. Replay of a consumed
member revokes the family's live descendants without touching the session (`EV-31`); session
expiry, a missing session row, application max-age, and scope removal revoke the family inside
the rejecting transaction (`EV-32`); `offline_access` is advertised in Discovery (`AC-12`). A code
whose current application has refresh disabled follows `EV-11`/`EV-13`: generic `invalid_grant`,
no consumption, and no family. Legacy validation, rotation, and revocation fail closed on any
interactive row (`EV-33`). This document itself activates no route or metadata beyond what its
slices delivered (`AC-14`).

The structural URI rules, current application state, complete-registration checks, and rejection of
unconsumed artifacts after registration removal are defined in
[the canonical model](./CanonicalSemanticModel.md#current-redirect-transport-trust).
HTTP and HTTPS are accepted equally in every environment; transport protection is a deployment
responsibility under ADR 0008.
