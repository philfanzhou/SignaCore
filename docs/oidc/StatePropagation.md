# Non-refresh State Propagation

**Status: target design.** Read the [directory boundary](./README.md) and the
[canonical model](./CanonicalSemanticModel.md) first.

The canonical event table is the sole normative state-transition matrix. This document is a
verification ledger: it connects each non-refresh trigger to the implementation read/write boundary
and end-to-end proof that must enforce the canonical row. It intentionally has no refresh-family
outcome column; the refresh-family contract owns that projection.

## Verification ledger

| Trigger group | Canonical source | Implementation owner or read point | Required proof |
| --- | --- | --- | --- |
| Missing one-time or authority row | `EV-03`, `EV-22` | Login continuation, code, session, and logout-handle digest lookups | `SC-18`; no guessed row, consumption, revocation, or replay audit |
| Session idle/absolute expiry | `EV-04` | Authorization, code redemption, and UserInfo each compare one captured UTC time; cleanup is not the enforcement mechanism | `SC-10` and exact-boundary cases |
| Application session max-age | `EV-05` | Authorization, code redemption, and UserInfo load current per-application policy against immutable `auth_time` | Exact-boundary and unaffected second-application cases |
| Prepared logout and its code race | `EV-06`, `EV-07`, `EV-28` | Browser completion owns handle consumption; session-first transaction owns matching revocation | `SC-05`, `SC-06`, `SC-15` |
| Account disable/delete | `EV-08` | Account-state transaction owns session revocation; authorization, code, and UserInfo retain live reads | Disable/delete between code issue and each live read; unaffected second-account case |
| Application deactivation | `EV-09` | Application-state transaction and every application-specific endpoint read | `SC-12` |
| Authorization-code capability off | `EV-10` | Application update plus authorization/code capability reads | Pending, new, and already-issued-code cases |
| Refresh capability off, non-refresh projection | `EV-11` | Authorization/code check `offline_access`; UserInfo ignores it; session is unchanged | Requests with and without `offline_access` |
| Redirect URI removal | `EV-12` | Authorization revalidates current registration; code redemption uses its exact stored snapshot | Removed-while-pending and removed-after-code cases |
| Scope removal | `EV-13` | Authorization/code use current allow list; UserInfo intersects it with token scope | `SC-11` |
| Administrative session revocation | `EV-15` | Session-admin transaction owns named revocation; code and UserInfo retain live reads | Named-session and unaffected-sibling-session cases |
| Signing-key rotation | `EV-16` | Issuance selects current key; validation/JWKS retention protects existing tokens and logout hints | Old-token-to-`exp` and 24-hour hint cases |
| Caller cancellation and commit failure | `EV-18` | Each explicit transaction owns rollback; response construction stays behind commit | `SC-20` plus forced persistence/audit failures |
| Correctly bound committed code replay | `EV-24` | Code redemption locks session then code and follows only the stored family link | `SC-08`, `SC-09`; sibling effect derives only from session state |

The ledger is complete only when the named owner and proof exist on both supported providers where a
transaction is involved. A link or passing Markdown check does not establish the scenario result.

## Cross-cutting enforcement rules

State rejection does not consume an otherwise unconsumed code and does not produce a replay audit.
Only committed prior consumption proves replay (`EV-23`, `EV-24`). A missing lookup likewise cannot
authorize a guessed session or family.

Identity-session revocation and application/account changes are live inputs to code redemption and
UserInfo. They do not remotely erase or shorten self-contained access or ID tokens: downstream
validation continues to `exp`, while UserInfo performs its separate current-state read. Application
session max-age never becomes a global session revocation.

Each state-changing operation owns its complete transaction. Account/application changes write all
promised explicit revocations with the setting change; prepared logout owns request consumption and
session/family revocation; administrative revocation owns the named session and its bound families.
Endpoints must not rely on cleanup to make those changes effective.

Every transaction uses one captured UTC time, locks the session before code/family/logout artifacts,
runs inside the provider execution strategy, and exposes no success artifact before commit
(`PS-22`). Cleanup preserves retained replay and referential-integrity facts. Vague intermediate
states are not part of the contract: an artifact is missing, live, expired, revoked, consumed, or a
proved replay as defined by the canonical model.

## Compatibility and activation

These rules do not add token introspection or remote access-token revocation. They do not change
current grants, admin cookies, `/api/profile/*`, application settings, migration history, or runtime
routes. Refresh-family event results remain exclusively owned by the later refresh-family document
and implementation tasks.

Session persistence and cross-endpoint propagation activate through #67 and #69 (`AC-09`). UserInfo
and prepared logout activate independently through #55/#96 and #68 (`AC-08`, `AC-10`). Documentation
completion alone changes no metadata or capability (`AC-14`).
