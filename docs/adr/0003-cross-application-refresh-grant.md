# ADR 0003: Cross-application Refresh Grant

- Status: Accepted
- Date: 2026-08-16

## Context

A refresh token is bound to the application that obtained it. `RefreshTokenValidator` rejects a
refresh grant whose stored `AppId` differs from the authenticated caller's, and
`RefreshTokenService` rotates on every refresh — the presented token is revoked and replaced.

Deployments exist where several registered applications serve one account population — commonly a
self-service application and one or more staff-facing applications, all backed by the same accounts.
A user signed in to one of them expects to reach another without re-authenticating. The only
credential such an application holds on the user's behalf is the refresh token it was issued, so the
target application presents that token under its own client credentials. Under the binding rule that
request is rejected.

This has been decided twice before, in opposite directions. An earlier change removed the binding
check outright to make this flow work; a later hardening change restored it and inverted the test
that covered the cross-application case. Neither change recorded a decision, so the second one read
as a straightforward tightening and silently removed a capability a deployment depended on. This ADR
exists so the next reader finds the trade-off instead of the oscillation.

Three properties of the current code decide the shape of any answer:

1. **Rotation revokes the presented token.** If a cross-application refresh reuses the rotation path,
   the source application's session dies as a side effect of the target application starting one.
   The earlier permissive change carried this defect; it was invisible until the source
   application's access token expired.
2. **Admission is per application.** The refresh path already re-checks LDAP, SMS, and WeChat
   admission against the *calling* application, not the token's. So relaxing the `AppId` comparison
   alone does not make the flow work: a user who never signed in to the target application has no
   admission row there and is rejected a few lines later, with a message about revoked access that
   describes a different situation.
3. **Admission is provisioned as evidence of authentication.** `SmsValidator` writes an admission row
   only after an OTP is verified, and records `SmsAccessApprovalSource.AutoProvision`. A refresh
   grant verifies no OTP. Writing that same approval source from an exchange would make the audit
   trail claim an authentication that never happened.

## Decision

Support cross-application refresh grants as an explicit, administered relationship. The concept is a
**cross-application refresh grant**; it is deliberately not called single sign-on, which in OAuth
terms means session reuse at an authorization endpoint — a surface this service does not have.

**Trust is a directed edge, stored in `app_exchange_trusts`.** Columns `app_registration_id` and
`source_app_registration_id` are both foreign keys to `app_registrations.id`, unique together, with
creation time and actor. The row means: `app_registration_id` accepts refresh tokens issued to
`source_app_registration_id`. It does not imply the reverse. The edge is ignored when either
application is inactive, and an application may not trust itself.

**A cross-application refresh mints; it does not rotate.** The source token is left untouched and a
new refresh token is issued, bound to the calling application. The two sessions are independent from
that point on.

**Admission propagates, but is recorded as what it is.** When the target application's admission mode
is `AutoProvision`, the exchange provisions the target's admission row with a new approval source
`ExchangeGranted`, distinct from `AutoProvision`. When the mode is `ManualApproval`, an
administrator-approved row must already exist. When it is `Disabled`, the exchange is rejected. The
same rule applies to the LDAP and WeChat admission paths.

**Exchange may continue across hops (amended 2026-10-21).** The nullable `source_app_id`
records the immediate source of a cross-application mint; it no longer prevents another exchange.
Each request checks the presented token's current `AppId` against the target's explicit directed
trust and rechecks the account, application and credential admission. `A → B` and `B → C` allow
A-to-B-to-C, but do not authorize a direct A-to-C request. The target callback and downstream
authorization still determine business permissions. This change applies to all configured legacy
exchange trusts, not only one consumer; interactive OIDC token families remain excluded.

No schema, wire format, expiration, ordinary rotation or revocation policy changes. Existing tokens
can participate without migration. Deploy this provider behavior before consumers that depend on
continuous exchange. Rolling back removes onward exchange while preserving ordinary login and
same-application refresh.

**The edge is an authentication-scope decision, not an authorization one.** It says the target
application may start a session for an account that authenticated elsewhere. It says nothing about
what that account may do. Role and permission constraints belong to the registered callback and to
the downstream application.

## Consequences

- Adding an edge grants every holder of a source-application refresh token the ability to obtain a
  target-application session for the same account. If the target application is more privileged than
  the source, that difference must be enforced by the target's callback and authorization rules, not
  by the absence of an edge. Administrators need to be told this at the point where they add one.
- Compromise of an application's refresh token store can reach applications reachable along
  configured directed paths, subject to their admission and authorization. Administrators must
  review this reachable set when adding or removing trust; there is no longer single-hop containment.
- `ExchangeGranted` admission rows record access that no OTP, directory bind, or WeChat authorization
  ever established for that application. Reviewing admission by approval source stays meaningful, and
  an operator can find every access that exists only because of an exchange.
- Revocation is asymmetric by construction. Revoking the source application's admission or refresh
  token does not end sessions minted from it, because those are bound to the target application and
  its own admission row. Ending a user's access everywhere means revoking per application, or
  disabling the account.
- The default is unchanged behaviour: with no rows in `app_exchange_trusts`, the binding check
  rejects exactly as it does today. Deployments that do not need this never see it.
- Three migration histories gain one table, one column on `refresh_tokens`, and one enum value per
  admission approval source.

## Alternatives considered

- **Removing the `AppId` binding check.** Rejected. It was tried, and it makes every application's
  refresh token usable at every other one, with no record of intent and nothing for an administrator
  to review or revoke. It also leaves the rotation defect in place.
- **A symmetric group column on `app_registrations`.** Rejected. The relationship is directional in
  practice — a user-facing application's token should reach a staff application, not the reverse —
  and a shared group value cannot express that. It also expands silently: adding a fourth
  application to the group grants every existing member access to it and it to them, in one edit
  that looks like a single change.
- **A list of trusted source application ids on `app_registrations`.** Rejected. Directional, but
  the list is a single value: there is no per-edge creation time or actor, no foreign key, and
  deleting an application leaves dangling ids. Auditing an edit means diffing snapshots.
- **Treating an exchange as equivalent to a login.** Rejected. It would provision admission with the
  approval source used for verified authentication, count towards login metrics and lockout, and
  erase the distinction between direct authentication and exchange. The audit trail would stop distinguishing an authentication from a derivation
  of one, which is the distinction this service exists to record.
- **Requiring pre-existing admission at the target.** Rejected as the default. It is the safest rule
  and needs no new enum value, but it means a user reaches the target application only after
  authenticating there directly at least once — which is the flow the feature exists to avoid.
  Deployments that want this rule keep the target application on `ManualApproval`.
