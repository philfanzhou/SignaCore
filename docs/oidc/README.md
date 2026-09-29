# Interactive OIDC Target Design

**Status: target design. None of the capabilities in this directory is implemented merely because
it is documented here.** For current behavior, see
[Standards Conformance](../overview/StandardsConformance.md).

The [canonical semantic model](./CanonicalSemanticModel.md) is the sole normative source for state
transitions, persistence relationships, external-input rules, sensitive-value flows, and staged
capability activation. Explanatory documents in this directory cite its stable row identifiers and
must not redefine them. If prose and a canonical row disagree, the canonical row wins and the prose
is corrected before implementation.

## Documents

| Document | Purpose |
| --- | --- |
| [Canonical Semantic Model](./CanonicalSemanticModel.md) | Normative `EV-*`, `PS-*`, `IN-*`, `DF-*`, `AC-*`, and `SC-*` decisions |
| [Interactive Client Model](./ClientModel.md) | Confidential-BFF registration, redirect URI ownership, scope policy, and compatibility |
| [Authorization Endpoint](./AuthorizationEndpoint.md) | Browser request orchestration, validation stages, safe error routing, and response boundary |
| [Identity Login](./IdentityLogin.md) | Isolated identity cookie, server-side continuation, Password login, SMS one-time-code login, CSRF, cancellation, and revalidation |
| [Authorization Code Redemption](./TokenEndpoint.md) | Code storage, token request validation, atomic redemption, replay, and transaction boundaries |
| [Interactive Tokens](./Tokens.md) | ID-token and access-token claims, lifetimes, consumers, validation duties, and response separation |
| [Identity Sessions](./IdentitySession.md) | Database authority, lifetime, activity, revocation, cleanup, and endpoint projections |
| [UserInfo](./UserInfo.md) | Bearer input, live-authority validation, claims, errors, and server-only response boundary |
| [Prepared Logout](./Logout.md) | Authenticated preparation, browser handle completion, redirects, sensitive values, and races |
| [Non-refresh State Propagation](./StatePropagation.md) | Verification ledger from state events to implementation and test owners |
| [Interactive Refresh Families](./RefreshTokens.md) | Refresh input, family rotation, reuse handling, state enforcement, and legacy isolation |
| [Interactive Persistence](./Persistence.md) | Additive family schema, legacy backfill, provider symmetry, cleanup, and rollback gates |
| [Security Contract](./Security.md) | Attack verification, audit, metrics, rate limits, sensitive-value canaries, and production gate |
| [Discovery Activation](./Discovery.md) | Current metadata facts, real implementation dependencies, and staged publication |
| [Ownership](./Ownership.md) | SignaCore, ServiceMantle, BFF, resource-service, and operator boundaries |
| [Integration Audit](./IntegrationAudit.md) | Final semantic replay of every canonical end-to-end scenario |
| [Multi-Instance Acceptance](./MultiInstanceAcceptance.md) | Two-instance OIDC acceptance base: A/B routing, per-dependency negative self-checks, and secret discipline |

The architectural choice and rejected alternatives are recorded in
[ADR 0005](../adr/0005-interactive-oidc-confidential-bff.md). Together these documents complete the
design baseline; runtime activation still follows `AC-01..17` and the open implementation tasks.

## First-phase boundary

The first client is a pre-registered, first-party, confidential BFF. The BFF keeps its client secret,
PKCE verifier, and every token server-side. The browser carries the authorization request, the
single-use authorization code, opaque SignaCore login/session handles, and the BFF's own unrelated
session cookie.

A Public browser client is available only through explicit per-application opt-in: Code with S256
PKCE, exact registered Origins, 300-second access tokens, and optional bounded refresh. The
[Public SPA sample](../../samples/SignaCore.PublicSpa/README.md) shows that path and its limits; the
confidential BFF remains the preferred client for high-privilege applications. The design adds no
consent screen, dynamic registration, MFA, browser LDAP/WeChat login, or new behavior to existing
grants. Browser SMS login is active through `AC-15`–`AC-17` (canonical rows `IN-16`–`IN-19`,
`EV-35`–`EV-38`, `DF-16`–`DF-17`, `SC-21`–`SC-26`): its storage (`AC-15`), its send route
`POST /oauth2/login/sms-code` (`AC-16`), and `action=sms_login` with the login page's SMS region
(`AC-17`). For an application whose `IN-19` gate is closed, the Password credential remains the only
browser login. A claims callback remains a server-to-server claims source; it is never a browser
redirect registration.

## Accepted extension

[ADR 0006](../adr/0006-hosted-login-localization-and-browser-sms.md) accepts browser SMS login and
a `zh-CN`/`en` localized login page as the next extension of this boundary. The browser SMS
contract is fixed by the canonical rows named above
([#441](https://github.com/philfanzhou/SignaCore/issues/441)), and its `AC-15`–`AC-17`
implementation slices are delivered.
