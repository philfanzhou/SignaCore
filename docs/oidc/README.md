# Interactive OIDC Protocol Contract

**Status: target design. None of this is implemented yet.**

This directory is the single normative source for the OIDC Authorization Code + S256 PKCE
capability described in [ADR 0005](../adr/0005-interactive-oidc-authorization-code.md). Every
implementation task under the "OIDC BFF v1" milestone builds against these contracts; where an
implementation and this directory disagree, one of the two is a defect and the disagreement is
resolved before the pull request merges.

For what SignaCore implements **today**, read
[StandardsConformance](../overview/StandardsConformance.md). The running service is an OAuth 2.0
authorization server and is not an OpenID Provider.

## Contents

| Document | Contract |
| --- | --- |
| [ClientModel](./ClientModel.md) | Interactive client configuration, redirect URIs, scopes, and why a callback is not a redirect URI |
| [AuthorizationEndpoint](./AuthorizationEndpoint.md) | `GET /oauth2/authorize` parameters, validation order, error routing, and the authorization response |
| [IdentitySession](./IdentitySession.md) | The identity cookie scheme, login continuation, login CSRF, and cancellation |
| [TokenEndpoint](./TokenEndpoint.md) | `authorization_code` redemption, PKCE verification, and atomic single-use consumption |
| [Tokens](./Tokens.md) | ID token, access token, and refresh token claims, lifetimes, rotation, and revocation |
| [UserInfo](./UserInfo.md) | `/oauth2/userinfo` request, response, and error contract |
| [Logout](./Logout.md) | RP-initiated logout and post-logout redirect |
| [StatePropagation](./StatePropagation.md) | What account disablement, application deactivation, logout, and revocation invalidate, and when |
| [Security](./Security.md) | Cookie and CSRF rules, the attack matrix, rate limiting, audit events, metrics, and sensitive-value handling |
| [Persistence](./Persistence.md) | New tables, both migration histories, PostgreSQL multi-instance and SQLite single-instance boundaries |
| [Discovery](./Discovery.md) | Which discovery field may appear after which capability ships |
| [Ownership](./Ownership.md) | ServiceMantle and SignaCore responsibility split |

## Scope of the first phase

The reference client is a **pre-registered, first-party, confidential BFF**: a server-side web
application that holds a client secret, keeps tokens server-side, and gives the browser nothing but
its own session cookie.

| Delivered | Not delivered in this phase |
| --- | --- |
| `GET /oauth2/authorize` with `response_type=code` | Any other response type or response mode |
| Mandatory PKCE, `S256` only | `plain`, or PKCE as per-client policy |
| Exact-match registered redirect URIs | Wildcard, prefix, or pattern matching |
| Browser identity session, Password credential only | SMS, LDAP, or WeChat browser login |
| `openid`, `profile`, `offline_access` | Any other scope, or dynamic scope registration |
| `id_token`, `/oauth2/userinfo` | Aggregated or distributed claims, `claims` parameter |
| RP-initiated logout with post-logout redirect | Front-channel or back-channel logout |
| Refresh token when the application allows it and `offline_access` is granted | Refresh token by default |
| Refresh-token families with reuse detection and descendant revocation | Reuse detection for the existing non-interactive grants |
| PostgreSQL multi-instance, SQLite single-instance | SQLite multi-instance |

Explicit non-goals for this phase. Public SPA clients are tracked as a separate epic; MFA and
step-up authentication are deliberately unscheduled, not merely deferred; the rest are out of scope
entirely: dynamic client registration, third-party self-service onboarding, a consent screen, social
login aggregation, SAML, Device Authorization Grant, Token Exchange, and centralised management of
downstream services' fine-grained permissions.

Nothing in this design may assume MFA is coming. Where a field exists in the specifications to carry
authentication strength — `acr`, `acr_values`, `max_age`, `prompt` — this phase either omits it or
rejects it outright, rather than reserving a shape for an unscheduled feature. See
[Tokens](./Tokens.md) and [AuthorizationEndpoint](./AuthorizationEndpoint.md).

## Definition of done for the first phase

The capability is complete when all of the following hold:

1. A reference administrative BFF completes Authorization Code + S256 PKCE login against SignaCore,
   and neither that service nor the browser ever sees the administrator's password.
2. An unregistered redirect URI, or one differing by case, path, port, or trailing slash, fails.
3. A request without PKCE, with `plain`, or with a wrong `code_verifier` fails at redemption.
4. An authorization code succeeds at most once, including under concurrent redemption, and a replay
   revokes what the first redemption produced.
5. The authorization request and the token request may land on different instances and still
   succeed, on PostgreSQL.
6. Replaying a consumed refresh token revokes every live descendant of its family, consistently
   across instances.
7. Issuer, signature, lifetime, audience, and `nonce` on the ID token are all verifiable by the
   client, and a token minted for one application is rejected by another.
8. A downstream service grants and revokes its own administrator role from `issuer + subject` alone.
9. No password, authorization code, `code_verifier`, token, cookie value, client secret, or
   `Authorization` header appears in any log or audit record.
10. Discovery advertises exactly the capabilities that exist.
11. Every existing grant, the legacy `/api/auth/*` contract, existing callbacks, shared-audience
    applications, and `qz_admin_session` behave exactly as they did before.

## Conventions used in these documents

- **MUST / MUST NOT / SHOULD / MAY** carry their RFC 2119 meanings.
- Every externally supplied field is specified with its encoding, length bounds, normalization,
  comparison rule, and the error produced when it fails. "Exact comparison" means ordinal,
  case-sensitive, byte-for-byte equality with no normalization at comparison time.
- Examples use placeholder values that are structurally valid and cryptographically meaningless.
  No example contains a real secret, code, token, cookie value, or person's data.
- Times are UTC. Durations named as defaults are settings in `system_settings` unless stated
  otherwise; durations named as invariants are not configurable.
