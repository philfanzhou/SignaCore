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

Later tasks add Token, UserInfo, logout, refresh-family, persistence, security, ownership, Discovery,
and ADR explanations. Until those tasks close, their canonical rows remain target decisions without
a second prose contract.

## First-phase boundary

The first client is a pre-registered, first-party, confidential BFF. The BFF keeps its client secret,
PKCE verifier, and every token server-side. The browser carries the authorization request, the
single-use authorization code, opaque SignaCore login/session handles, and the BFF's own unrelated
session cookie.

The design adds no public client, consent screen, dynamic registration, MFA, browser SMS/LDAP/WeChat
login, or new behavior to existing grants. A claims callback remains a server-to-server claims
source; it is never a browser redirect registration.
