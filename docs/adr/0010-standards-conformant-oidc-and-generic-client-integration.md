# Standards-Conformant OIDC and a Generic-Client Integration Path

- Status: Accepted (stages 1, 2, and 4 delivered; stage 5 in progress; stage 3 optional, deferred)
- Date: 2026-11-11
- Decision owners: SignaCore maintainers
- Extends: [ADR 0005](./0005-interactive-oidc-confidential-bff.md), [ADR 0007](./0007-official-hosted-login-client-package.md)

## Context

SignaCore has three distinct integration roles, only one of which uses the official client
package:

1. **Resource servers** validate incoming RS256 Bearer JWTs locally (Discovery + JWKS, issuer,
   audience, lifetime). No SignaCore code is involved; any framework JWT handler works. Emenda
   integrates this way with zero SignaCore dependencies, which is exactly the boundary
   [ADR 0007](./0007-official-hosted-login-client-package.md) draws: the package "is not a
   token-validation library".
2. **First-party end-user portals** authenticate users through the legacy `/api/auth/*`
   contract (password/SMS grants over a server-to-server call with application credentials).
   No browser redirect to SignaCore occurs, so no OIDC client machinery is needed.
3. **Confidential browser clients** (the five administrator consoles: Doctheca, Lexarbor,
   Quaestura, Ruoyu.Admin, Ruoyu.Study AdminConsole) run the interactive Authorization Code +
   PKCE flow against the hosted login page. This is the sole consumer of
   `SignaCore.Client.AspNetCore`.

The package exists because SignaCore is a **profiled provider**, not a fully conformant OpenID
Provider. Four deltas make generic framework OIDC clients (for example
`Microsoft.AspNetCore.Authentication.OpenIdConnect`, Spring Security OAuth2 Client,
openid-client) unusable today:

- **Logout is intentionally non-standard.** Discovery
  (`src/SignaCore.Host/DiscoveryDocument.cs`) publishes no `end_session_endpoint`; sign-out
  runs through the custom prepared-logout transport, and ADR 0007's standards basis states
  this "is intentionally not a claim of RP-Initiated Logout 1.0 conformance".
- **The authorization request is a hard subset.**
  `OidcAuthorizationRequestValidator` rejects `prompt`, `max_age`, `acr_values`,
  `response_mode`, and `request_uri`, while generic handlers expect at least
  `prompt`-aware behavior.
- **Session semantics are inverted.** Generic handlers carry the principal (and often tokens)
  in an authentication cookie with optional silent refresh. SignaCore's model — tokens stay
  server-side behind one opaque cookie, no silent refresh, re-authentication through the
  hosted page (ADR 0005) — is the opposite default.
- **The strict response-validation profile** (zero clock skew by default, scope-echo subset,
  duplicate-JSON-member rejection, bounded token/logout response sizes, future-`iat`
  rejection) has no equivalent switch in generic handlers.

Against that, fully conformant providers (Keycloak among them) need no vendor-specific
server-side package: a generic client plus the issuer URL completes login *and* standard
logout from Discovery alone. The vendor package remains necessary exactly where the provider
deviates.

The coupling cost of the package has been observed directly:

- 0.1.16 removed the public `IntranetHttpOrigins` option on a patch release (its own README
  labelled it "Version 0.2.0 is a breaking change");
- 0.1.22 shipped source-breaking public-type renames on a patch release;
- the ADR 0007 compatibility promise ("client X.Y supports server X.Y and X.(Y-1), CI
  contract tests cover the promised matrix") is enforced only as *current package × current
  host*; no job restores an old published package against a new host.

## Decision (proposed)

Make SignaCore integrable by **generic, standards-based OIDC clients with no SignaCore-specific
package**, while keeping the existing package and legacy contract working throughout. Staged:

1. **Standard logout alongside the prepared logout.** Publish `end_session_endpoint` in
   Discovery and accept OIDC RP-Initiated Logout requests (`id_token_hint`, optional
   `post_logout_redirect_uri` and `state`, exact-registration matching) on that endpoint. The
   existing one-time-handle completion and the prepared-logout backchannel remain unchanged
   for package consumers. Acceptance: a consumer configured only with a generic handler can
   end its session through the standard endpoint. — **Delivered**: the endpoint is
   `GET /oauth2/session/end`; it resolves the application from the hint's single `aud` claim,
   applies the shared `IN-31` hint judgement, stages the identical one-time request, and
   immediately completes it with the browser's identity cookie, so the `EV-06`/`EV-07`
   session semantics, the `EV-28` lock order, and the audit rows are byte-for-byte the
   prepared flow's (see [Logout](../oidc/Logout.md)).
2. **Define standard-parameter semantics on the authorization endpoint.** Stop hard-rejecting
   the parameter set generic clients send: accept `prompt=login` (force re-authentication),
   answer `prompt=none` from the live identity session when one exists (the session-reuse
   service already backs this) and with `login_required` otherwise, and accept or
   safely ignore `max_age`/`acr_values` per a written table. The rejection of `response_mode`
   values other than `query` and of `request`/`request_uri` may remain, documented. —
   **Delivered**: `prompt` accepts exactly `none` or `login`; `max_age` (0–2592000 seconds) is
   enforced against the session's `auth_time` under the session-row lock in the reuse
   transaction (`0` refuses every reuse); `acr_values` is accepted within a printable-ASCII
   bound and ignored; `response_mode=query` is accepted explicitly and every other value is
   `unsupported_response_mode`; `prompt=none` without a usable session answers the standard
   `login_required` error redirect and never renders the login form (see
   [AuthorizationEndpoint](../oidc/AuthorizationEndpoint.md)).
3. **Optional session-management alignment.** Evaluate back-channel logout (and, only if it
   earns its keep, the session-management iframe) so generic clients learn when the SignaCore
   identity session ends, instead of discovering it at token expiry.
4. **Prove the generic path continuously.** Add an official sample and a CI job that talks to
   the real host using only `Microsoft.AspNetCore.Authentication.OpenIdConnect` — no
   `SignaCore.Client.AspNetCore`. This simultaneously converts the paper compatibility
   promise into an enforced matrix and keeps future regressions visible. — **Delivered**:
   [samples/SignaCore.GenericOidc](../../samples/SignaCore.GenericOidc/README.md) is the
   sample, and `GenericOidcClientFlowTests` (in the integration assembly, so it runs in the
   ordinary CI build and test job) drives it against the real host through the whole lifecycle:
   Discovery, the code + PKCE S256 authorization request, the hosted login form, the token
   redemption, the local cookie session, and the stage-1 standard RP-Initiated Logout with the
   SignaCore identity session revoked end to end.
   Administrator sign-in is covered through the framework's verified ID-token principal before
   its session cookie is written. A Confidential client granted `profile` can map `role` to
   `admin` for the password-authenticated bootstrap administrator. See the
   [ID token contract](../oidc/Tokens.md#id-token) for issuance and refresh behavior.
5. **Deprecate the package along a published window.** Once stage 4 has run green across
   releases: freeze package features (security fixes only), mark it deprecated for *new*
   integrations in favor of the generic path, keep maintaining it for the five existing
   consoles until each migrates, and offer the strict validation profile either as a small
   optional add-on or as contributions upstream. The five consoles' adaptation layers keep
   working unchanged for as long as they stay on the package. — **In progress**: with stage 4
   delivered and green across releases, the package README carries the deprecation notice, the
   NuGet.org listing is flagged deprecated (an account-side owner action recorded outside this
   repository), and features are frozen. Retirement completes when the remaining consumers —
   the Doctheca, Lexarbor, Quaestura, and Ruoyu.Study administrator consoles (Ruoyu.Admin is
   already retired) — migrate to the generic handler.

The resource-server guidance (plain framework JWT handler, as Emenda integrates) and the
legacy first-party `/api/auth/*` contract are unaffected by this decision.

## Consequences

- Consumers that migrate can drop a vendor dependency and inherit protocol and security
  maintenance from framework handlers maintained at ecosystem scale; SignaCore's
  compatibility surface shrinks to "standard OIDC", and the package's release-discipline
  problems stop mattering to new integrations.
- A generic-handler consumer keeps its own session model by default (authentication cookie).
  A console that wants SignaCore's server-side-ticket posture must configure its own ticket
  store — a standard ASP.NET Core extension point — so the posture survives the migration but
  is no longer owned by SignaCore.
- SignaCore takes on the server-side work: standard logout with exact-registration checks,
  parameter semantics with their threat model re-derived (every newly accepted parameter is a
  new external-input surface), and conformance testing. Dual logout paths must stay
  consistent by contract tests on both.
- The existing consoles, the NuGet-published package history, and the legacy API are not
  broken by any stage; risk is bounded by the ordering (server conformance first, consumer
  migration last, one console at a time).

## Alternatives considered

| Alternative | Reason rejected |
| --- | --- |
| Keep the package as the only sanctioned interactive client (status quo) | Retains the observed patch-level breaking-release coupling and leaves the compatibility promise unenforced across versions |
| Rebuild the package on a generic third-party OIDC client library | Rejected in ADR 0007: SignaCore's prepared logout, strict validation, session-expiry re-authentication, and redaction duties do not map onto a generic handler without re-deriving the same hardening |
| Consumers hand-roll the protocol (the pre-#479 state) | Every protocol or security fix must be repeated in every consumer; each historical self-written slice took multiple review rounds (Doctheca #79 replaced exactly such a slice) |
| Tell browser consoles to use the legacy password API instead | Administrator credentials would flow through every consumer's own pages — the exposure ADR 0005's hosted login exists to prevent — and central logout is lost |

## Standards basis

OpenID Connect Core 1.0, OpenID Connect Discovery 1.0, OpenID Connect RP-Initiated Logout 1.0,
OpenID Connect Back-Channel Logout 1.0 (optional stage), [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207).
The prepared-logout transport remains a documented SignaCore extension for package consumers
and is not withdrawn by this decision.
