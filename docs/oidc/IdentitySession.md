# Identity Sessions

**Status: target design.** Read the [directory boundary](./README.md) and the
[canonical model](./CanonicalSemanticModel.md) first.

An identity session is the database authority for one Password-authenticated browser identity. The
identity cookie is only a protected carrier for its opaque identifier. A successfully unprotected
cookie is therefore not proof that the session, account, or application-specific authentication
age is currently usable.

## Authority and isolation

Canonical `PS-04` owns the session record and `PS-18` owns the identity cookie. The session binds an
account and the Password credential that proved it, records `auth_time`, activity, idle and absolute
expiry, and carries optional revocation facts. The cookie contains none of those facts and never
becomes a self-contained session ticket.

The identity scheme remains isolated from the current `qz_admin_session` exactly as described in
[Identity Login](./IdentityLogin.md). Administration cannot create, slide, or revoke an identity
session, except through the future explicit session-administration operation in `EV-15`. OIDC
identity endpoints never accept the admin cookie, and the existing admin logout route remains
unchanged.

## Lifetime and activity

One captured UTC operation time is used for every comparison and write in a request. Equality with
an expiry is expired. A new session has a 30-minute sliding idle window and a 12-hour absolute
limit. A successful browser authorization may advance activity only when the stored activity is at
least one minute stale, and the new idle expiry is capped by the absolute expiry (`PS-04`). Login,
refresh, UserInfo, logout preparation, and failed authorization do not slide the session.

Application session max-age is a live, application-specific check against the session's immutable
`auth_time`. Reaching or reducing that limit does not revoke the global session and cannot affect a
different application (`EV-05`). It requires fresh identity login for the affected application.

Missing, expired, and revoked are distinct observations. A missing row supplies no authority and
causes no invented revocation or audit. Idle or absolute expiry is a time result, not a revocation
write (`EV-04`). A revoked row retains its time and reason for enforcement, audit correlation, and
retention.

## Endpoint projection

This table points to canonical outcomes; it does not redefine them.

| Read point | Missing, expired, or revoked authority | Usable authority |
| --- | --- | --- |
| Authorization endpoint | Start a new login flow; never recover identity from cookie claims | Apply application max-age, current account/application policy, and bounded activity sliding before issuing a result (`EV-04`, `EV-05`) |
| Code redemption | Generic `invalid_grant`; an unconsumed code remains unconsumed | Lock session before code and enforce every live predicate (`EV-20`–`EV-24`) |
| UserInfo | 401 `invalid_token`; no activity update | Return only the live-authorized `PS-16` projection; no activity update (`IN-29`) |
| Prepared logout completion | A missing or unusable cookie follows the oracle-free `EV-07` path | Exact request/session/account binding permits `EV-06`; logout itself never slides activity |

The authorization and login documents own how a browser is routed to fresh login. The token and
UserInfo documents own their protocol error envelopes. This session document owns neither a new
cookie input nor a shortcut around those validation stages.

## Revocation and state changes

Revocation paths lock the session row before related code, family, or logout-request state. They
write a captured UTC revocation time and a bounded reason. Logout uses `logout`, administrative
revocation uses `administrative`, and a correctly bound committed code replay uses `code_replay`.
Account disablement or deletion explicitly revokes every account session in the account-state
transaction (`EV-08`).

Application deactivation, authorization-code disablement, refresh disablement, redirect removal,
and scope removal do not globally revoke identity sessions (`EV-09`–`EV-13`). Those changes are
enforced at their application-specific read or write points. Signing-key rotation likewise changes
no session state (`EV-16`).

Revoking a session makes bound unconsumed codes fail their live check without consuming them. It
also makes UserInfo fail immediately, while already issued self-contained access and ID tokens keep
their downstream validity until `exp`. Refresh-family writes and outcomes are deliberately deferred
to the refresh-family contract.

## Concurrency, failure, and cleanup

All explicit transactions execute inside the provider execution strategy (`PS-22`). PostgreSQL
locks shared rows across instances. SQLite provides the same state machine for concurrent requests
to one SignaCore instance and one database writer; multi-instance SQLite is unsupported. Every path
that combines session and another stateful artifact locks the session first.

A durable session write commits before a browser response can expose its result. Cancellation,
persistence failure, or required audit failure before commit rolls the whole unit back; cancellation
after commit cannot undo it (`EV-18`). Cleanup may remove only expired/revoked sessions past their
retention point and after referential-integrity rules following `PS-22` allow it. It must not erase a
session while a retained code, logout request, or refresh-family fact still needs that authority or
audit correlation. For authorization codes that rule is also enforced by the schema: the code table
is created with a non-null restrictive reference to this authority (`PS-23`), so cleanup that would
strand a retained code fails instead of silently erasing evidence.

## Test mapping and compatibility

Tests use `SC-05`, `SC-06`, `SC-08`–`SC-12`, `SC-15`, `SC-18`, and `SC-20` rather than copying their
expected transitions here. They additionally prove exact-boundary expiry, the one-minute activity
write threshold, absolute-expiry capping, application max-age isolation, cross-scheme cookie
rejection, provider lock order, and cleanup referential integrity.

This design changes no current cookie, admin session, profile API, grant, migration, or runtime
route. Storage/lifecycle and state propagation activate only through #67 and #69 (`AC-09`), whose
#95 storage slice precedes the authorization-code table required by `AC-03`. This document itself
changes no Discovery metadata (`AC-14`).
