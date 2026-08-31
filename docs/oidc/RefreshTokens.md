# Interactive Refresh Families

**Status: target design.** Read the [directory boundary](./README.md), the
[canonical model](./CanonicalSemanticModel.md), and
[interactive persistence](./Persistence.md) first.

An interactive refresh token extends one confidential BFF authorization while its original
identity session and current application policy remain usable. It is an opaque, rotating credential,
not a browser token and not a portable account credential. Existing Password, SMS, LDAP, WeChat,
legacy refresh, and cross-application exchange behavior stays on its current path.

This design applies refresh-token rotation and relationship retention in the sense of
[RFC 9700 section 4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2). The narrower
input and no-scope-narrowing choices are the profile fixed by canonical `IN-26` and `IN-27`.

## Issue and request boundary

An authorization-code redemption creates a root only when the committed authorization snapshot
contains `offline_access` and current application policy allows refresh (`EV-21`). The raw root is
32 CSPRNG bytes encoded as 43 unpadded-base64url characters. Only its versioned SHA-256 digest is
stored (`DF-09`). The code records the exact root id, so two codes for the same
account/application/session/scope create distinct families and code replay never guesses one
(`PS-05`, `SC-07`–`SC-09`).

`POST /oauth2/token` uses the common 16 KiB form and confidential-client authentication from
`IN-20`. Duplicate supported/rejected parameters are `invalid_request`; unknown fields are ignored
by this branch. `grant_type` is exactly `refresh_token`. `refresh_token` is one 1–256-character ASCII
value: new interactive values are exactly 43 base64url characters, while previously issued legacy
shapes remain accepted for digest lookup (`IN-26`). `scope` must be absent and is
`invalid_request`; the family snapshot cannot be narrowed or replaced (`IN-27`).

After digest lookup, non-null `identity_session_id`, canonical `scope`, and `auth_time` together mark
an interactive member. All three null marks a legacy member (`PS-06`, `PS-07`). A partial marker,
cross-family relationship, or inconsistent account/application/session/scope binding is corrupt
state: fail closed with generic `invalid_grant`, emit only a non-secret internal diagnostic, and
perform no reuse side effect.

An interactive family is usable only by its exact authenticated confidential client. It never enters
the cross-application exchange-trust path from ADR 0003. `/api/auth/token` does not gain interactive
refresh behavior. Legacy rows continue through their current validators, admission checks, rotation,
error envelopes, token shapes, and cross-application minting (`EV-33`).

## Family lifetime and member states

Every member carries the same family id, account, application, identity session, canonical scope,
and original `auth_time`. A root has `family_id=id` and no parent. Each rotation appends exactly one
child whose parent is the presented member (`PS-06`).

The root fixes the family deadline to the earliest of the existing configured refresh-token duration,
seven days after root issue, and the session's absolute expiry. Every child copies that exact
deadline; rotation never extends the family. The session's 30-minute idle boundary is still read
live and is never slid by refresh.

Member states remain disjoint:

| Observation | Authority |
| --- | --- |
| Live | `consumed_at` is null, existing `is_revoked` is false, member/family time is before expiry, and every bound live predicate succeeds |
| Consumed | `consumed_at` records the committed rotation; this alone proves interactive reuse when the static client/family binding is correct |
| Explicitly revoked | Existing `is_revoked` is true because a named-token or state transaction revoked the member; this is not evidence of reuse |
| Expired | Captured UTC time equals or exceeds the member/family deadline; expiry is not consumption or revocation by itself |
| Missing | Digest lookup found no row; no family, session, or audit may be inferred |

A normal interactive rotation sets `consumed_at` but does not set `is_revoked`. A later family
revocation may also mark an already consumed member revoked; validation checks a correctly bound
`consumed_at` before expiry, revocation, or live-session state so retained proof cannot be erased by
a later event (`EV-31`). Wrong client or corrupt binding never reaches that side effect.

## Atomic rotation

Digest lookup may identify the member and session without granting authority. One captured UTC time
then drives a provider execution-strategy transaction:

1. Lock the referenced session when it exists, then the family root and presented member. Re-read
   the digest, marker, client, account, application, session, scope, parent, and family bindings.
2. If the correctly bound member is consumed, execute reuse handling below even when it is now
   expired or its session is missing/revoked. If it is merely missing, expired, or explicitly
   revoked, execute `EV-32` without reuse handling.
3. Recheck active account/application, refresh capability, the complete current scope allow list,
   session existence/revocation/idle/absolute expiry, and application max-age. Refresh never slides
   activity and never silently narrows scope.
4. Construct one stable request-local child id, raw token and digest, access token, nonce-free ID
   token, and audit result. A fallible signing or construction step must succeed before the parent
   can be consumed.
5. Conditionally set the still-live parent's `consumed_at`, insert the one child, and commit required
   audit/state writes together. A unique parent relationship remains a database backstop.
6. Release `PS-15` only after commit: one new access token, one ID token without `nonce`, unchanged
   canonical scope, and exactly one new refresh token. Original `sid` and `auth_time` are preserved.

The explicit transaction runs inside `PS-22`. Values generated for one HTTP attempt remain stable
across an execution-strategy retry. If commit acknowledgement is ambiguous, verification by that
stable child id/digest distinguishes this attempt's already committed child from another caller's
rotation. The former resumes the same response; the latter is reuse. A retry must never create a
second child or classify its own commit as an attack.

Signing, persistence, required audit, or commit failure before a verified commit rolls back
consumption and child creation and exposes no token bytes. Cancellation before commit has the same
result. After commit, state is authoritative; a lost response or caller retry presents a consumed
credential and follows reuse behavior (`EV-18`, `SC-16`, `SC-20`).

## Concurrent rotation and reuse

`EV-29` is the only successful transition. With two callers, the session/root/member locks,
conditional consumption, and unique parent allow exactly one child commit. The loser observes the
committed `consumed_at`, executes `EV-31`, returns generic `invalid_grant`, and revokes every live
descendant of the presented member. In the one-child chain this includes the winner's child, so at
most one child ever commits and none remains usable after detected reuse (`EV-30`, `SC-14`).

Reuse does not revoke the identity session and does not select another family for the same session,
account, application, or scope. It records one `oidc.refresh.replayed` audit with only the family id,
bounded member ids/count, application id, and correlation id. It never records the raw token or
digest. A consumed retained member proves reuse even when the session row is missing; a missing
token, expired member, or explicitly revoked member never manufactures reuse or an audit (`SC-18`).

PostgreSQL proves the race across separate SignaCore instances sharing one database. SQLite proves
the same result for concurrent requests to its supported single instance and writer. Multi-instance
SQLite remains unsupported (`PS-22`).

## State enforcement ledger

The canonical event table remains the normative result matrix. This ledger identifies the family
write/read owner and must not be used to infer a different outcome.

| Trigger | Canonical owner | Refresh enforcement |
| --- | --- | --- |
| Session idle/absolute expiry | `EV-04`, `EV-32` | Next refresh atomically revokes the family for session expiry, returns `invalid_grant`, creates no child, and emits no reuse audit |
| Application max-age | `EV-05`, `EV-32` | Next refresh atomically revokes that application's family for max-age, without global session change |
| Prepared logout | `EV-06` | Logout transaction explicitly revokes every family bound to the session before success |
| Logout without a matching usable cookie | `EV-07` | Logout-request consumption changes no family, session, code, or token state |
| Account disable/delete | `EV-08` | Account-state transaction explicitly revokes every account family with the account/session changes |
| Application deactivation | `EV-09` | Application-state transaction explicitly revokes that application's families; other applications and the session remain usable |
| Authorization-code capability off | `EV-10` | Existing families remain usable when refresh stays enabled and every scope remains allowed |
| Refresh capability off | `EV-11` | Setting-change transaction revokes every interactive family for the application; requests without `offline_access` may still authorize |
| Redirect URI removal | `EV-12` | No family write or new refresh rejection condition |
| Scope removal | `EV-13`, `EV-32` | The family is never narrowed; its next refresh atomically revokes the whole family and returns `invalid_grant` |
| `/oauth2/revoke` | `EV-14` | Revoke only the named live member owned by the authenticated application; family and siblings are unchanged |
| Administrative session revocation | `EV-15` | Session-state transaction explicitly revokes every family bound to that session; other sessions are unchanged |
| Signing-key rotation | `EV-16` | Family state is unchanged; a successful refresh uses the current `kid` |
| Correctly bound code replay | `EV-24` | Directly revoke only the exact root family linked by that code and revoke the session; sibling families become unusable only through the session check |
| Session row missing | `EV-32` | A still-retained family is atomically revoked for missing authority; no session is guessed and no reuse audit is emitted |

A canonical whole-family revocation sets `is_revoked` on every unrevoked retained member and commits
the closed cause in the triggering audit/state unit (`PS-11`). This is distinct from `EV-14`, which
marks only the named live member, and `EV-31`, which marks only live descendants of the consumed
member. A later refresh of an already explicitly revoked member adds no write. `EV-31` returns
`invalid_grant` with its one reuse audit; every other rejecting refresh row returns the same
`invalid_grant`, creates no child/access/ID token, and emits no reuse audit. `EV-10`, `EV-12`, and
`EV-16` permit the normal `EV-29` transition when every other predicate is live. Self-contained
access and ID tokens already issued remain valid to `exp`; SignaCore does not add introspection or
remote access-token revocation.

## Legacy and activation guarantees

Migration backfills every existing row as a singleton root. A legacy same-application rotation
keeps using `is_revoked` and creates a new singleton root; a cross-application exchange keeps minting
a separate singleton root with `source_app_id`. Neither sets an old row's `consumed_at`, creates a
parent link, triggers descendant revocation, changes claim/lifetime/response fields, or gains an
interactive session/scope binding (`PS-07`, `EV-33`). Existing `/oauth2/revoke`,
`/api/auth/revoke`, cleanup, and administration keep their wire shapes and named-token behavior.
The current standards legacy branch also retains its `invalid_scope` result for a supplied nonblank
scope; `IN-27`'s `invalid_request` is selected only for a positively identified interactive member.

#97 may add and backfill the family shape but must not issue interactive roots or advertise
`offline_access` (`AC-11`). Only #98, after live session enforcement, activates atomic interactive
rotation/reuse and adds `offline_access` to `scopes_supported` (`AC-12`). Existing advertised
`refresh_token` grant remains truthful throughout. This document itself changes no route, setting,
schema, or metadata (`AC-14`).

## Verification mapping

Tests execute canonical scenarios rather than copy their result into another state model:

| Proof | Canonical scenarios |
| --- | --- |
| Independent roots and exact code-replay family/null selection | `SC-07`, `SC-08`, `SC-09` |
| Session expiry, scope removal, and application deactivation | `SC-10`, `SC-11`, `SC-12` |
| Double rotation across the supported provider boundaries | `SC-14` |
| Signing or construction failure before commit | `SC-16` |
| Missing digest without guessed family/session or replay audit | `SC-18` |
| Cancellation before versus after rotation commit | `SC-20` |

The logout/code order in `SC-05` and `SC-06` additionally proves that an optional root is either
never created or is included in the later logout transaction. Provider tests also cover a correctly
bound consumed member after session deletion, exact token boundary lengths, absent versus supplied
scope, corrupt partial markers, legacy replay, commit-unknown retry verification, and explicit
single-member revocation.
