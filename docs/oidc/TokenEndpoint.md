# Authorization Code Redemption

**Status: target design.** Read the [directory boundary](./README.md) and the
[canonical model](./CanonicalSemanticModel.md) first.

`POST /oauth2/token` gains an `authorization_code` branch for pre-registered confidential BFFs.
The branch redeems one short-lived code for the response in `PS-14`; it does not reuse a browser
identity cookie as client authentication and does not add this grant to `/api/auth/token`.

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

The request `redirect_uri` is compared ordinally with the exact snapshot on the code, not normalized
and not compared with the client's current registration set. This preserves the `EV-12` decision:
removing a registration prevents new authorization but does not reinterpret an already issued
60-second code. The `scope` parameter is rejected because the authorization snapshot is authoritative
and cannot be narrowed during redemption.

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
6. For an unconsumed code, use one captured UTC time to check code expiry, current scope/refresh
   policy, live session including application max-age, active account, and active application.
   `EV-04`, `EV-05`, `EV-08`, `EV-09`, `EV-11`, and `EV-13` provide the state-specific result;
   rejection follows `EV-23` and leaves `consumed_at` null.
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
| Missing or failed client authentication | `IN-20`: 401 `invalid_client`; no code lookup side effect |
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
from creation (`PS-23`); #53 activates internal code redemption only (`AC-06`).
Discovery remains unchanged until #54 and its persistent-session prerequisites complete the whole
core flow (`AC-07`). This document itself activates no route or metadata (`AC-14`).
