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
| [Identity Login](./IdentityLogin.md) | Isolated identity cookie, server-side continuation, Password login, CSRF, cancellation, and revalidation |
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

The architectural choice and rejected alternatives are recorded in
[ADR 0005](../adr/0005-interactive-oidc-confidential-bff.md). Together these documents complete the
design baseline; runtime activation still follows `AC-01..14` and the open implementation tasks.

## First-phase boundary

The first client is a pre-registered, first-party, confidential BFF. The BFF keeps its client secret,
PKCE verifier, and every token server-side. The browser carries the authorization request, the
single-use authorization code, opaque SignaCore login/session handles, and the BFF's own unrelated
session cookie.

The design adds no public client, consent screen, dynamic registration, MFA, browser SMS/LDAP/WeChat
login, or new behavior to existing grants. A claims callback remains a server-to-server claims
source; it is never a browser redirect registration.
