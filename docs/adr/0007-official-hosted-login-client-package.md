# Official Hosted-Login Client Package

- Status: Accepted
- Date: 2026-10-01
- Decision owners: SignaCore maintainers
- Extends: [ADR 0005](./0005-interactive-oidc-confidential-bff.md)

## Context

[ADR 0005](./0005-interactive-oidc-confidential-bff.md) delivered the interactive Authorization
Code flow for pre-registered confidential BFF clients, and the
[Hosted Login guide](../integrations/HostedLogin.md) documents how a consuming service redirects
the browser to SignaCore, receives a one-time code at its registered callback, and validates the
issued tokens. The repository boundary so far has been that downstream systems integrate only over
HTTP — Discovery, JWKS, and the documented API and OAuth surfaces — and never reference this
repository's assemblies.

That boundary keeps the server internals closed, but it leaves every consumer to implement the same
confidential-client protocol duties on its own: authorization-request construction with PKCE S256,
callback hardening, strict ID-token validation, one-time state, a server-side session,
re-authentication after session expiry, prepared logout, and sensitive-value redaction in logs and
telemetry. The [Reference BFF sample](../../samples/SignaCore.ReferenceBff/README.md) and several
downstream services each carry such an implementation, each stabilized through multiple review
rounds; a protocol or security fix must currently be repeated in every consumer
([#479](https://github.com/philfanzhou/SignaCore/issues/479)).

This ADR amends the integration boundary so that SignaCore, as the protocol owner, can publish one
official client package, and it fixes that package's responsibilities, extension points,
versioning, release, compatibility promise, and dependency policy before any package code is
written. The package itself is implemented and released by the follow-up tasks tracked in
[#479](https://github.com/philfanzhou/SignaCore/issues/479); this ADR delivers documentation only
and changes no code, pipeline, or server HTTP contract.

The [canonical semantic model](../oidc/CanonicalSemanticModel.md) remains the only normative source
for SignaCore-side state transitions, external-input rules, and sensitive-value flows. The package
is an owned implementation of that model's
[caller responsibilities](../oidc/CanonicalSemanticModel.md#guarantees-and-caller-responsibilities);
this ADR does not restate a second state machine.

## Decision

### Amended integration boundary

- Downstream systems integrate with SignaCore either over pure HTTP — Discovery, JWKS, and the
  documented API and OAuth surfaces, as described in the
  [Hosted Login guide](../integrations/HostedLogin.md) — or by referencing the officially released
  client package `SignaCore.Client.AspNetCore`.
- The server-side assemblies (`SignaCore` host, `SignaCore.Domain`, `SignaCore.Database`, and the
  migration projects) are never published for downstream reference; referencing them remains
  forbidden.
- Pure HTTP integration remains supported and documented. The client package is an additional,
  owned implementation of the same public HTTP contract, not a replacement for it.
- The package contains no consumer business models, branding, or authorization rules; its samples
  use neutral names such as `OrderService`.

### Package responsibilities

In scope, owned by the package for Confidential clients on the interactive flow of ADR 0005:

| Duty | Normative source |
| --- | --- |
| Build the authorization request and register the exact callback: mandatory `state`/`nonce`, PKCE S256, exact registered `redirect_uri` | [IN-01..09](../oidc/CanonicalSemanticModel.md#authorization-and-identity-login), [PS-20, PS-21](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship), [Hosted Login step 4](../integrations/HostedLogin.md#4-send-the-browser-to-the-authorization-endpoint) |
| Harden the callback: validate `state` and `iss` before any token exchange, consume pending values exactly once, treat the code as a secret | [IN-01..09](../oidc/CanonicalSemanticModel.md#authorization-and-identity-login), [DF-03, DF-11](../oidc/CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow) |
| Redeem the code with client authentication and validate the ID token strictly (RS256 via JWKS `kid`, `typ`, `iss`, `aud`, `exp`/`iat`, `nonce`) | [IN-20..25](../oidc/CanonicalSemanticModel.md#token-and-userinfo), [PS-09, PS-12](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship), [Hosted Login step 5](../integrations/HostedLogin.md#5-redeem-the-code-and-validate-the-tokens) |
| Keep a server-side session and ticket store: every token stays server-side; the browser receives only the package's own opaque session cookie | [DF-07..09](../oidc/CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow), [caller responsibilities](../oidc/CanonicalSemanticModel.md#guarantees-and-caller-responsibilities) |
| Expose sign-in start, callback, and session-status endpoints for the consuming application, mounted under the consumer's route prefix | [Hosted Login guide](../integrations/HostedLogin.md) |
| Re-authenticate after the SignaCore identity session ends: route the browser through the authorization endpoint again and never keep a signed-in appearance over a dead upstream session | [EV-04, EV-05](../oidc/CanonicalSemanticModel.md#event--artifact--result), [SC-10](../oidc/CanonicalSemanticModel.md#end-to-end-semantic-scenarios), [Hosted Login session lifetime](../integrations/HostedLogin.md#8-session-lifetime) |
| Enforce a CSRF boundary on the package's own browser-facing POST endpoints | Package-internal hardening; the model's `IN-14`/`PS-19` govern SignaCore's own login form |
| Drive prepared logout: server-to-server preparation, then redirect the browser by one-time handle; no ID token in a browser URL | [IN-30..36](../oidc/CanonicalSemanticModel.md#logout-without-an-id-token-in-the-browser), [EV-06, EV-07](../oidc/CanonicalSemanticModel.md#event--artifact--result), [SC-15](../oidc/CanonicalSemanticModel.md#end-to-end-semantic-scenarios), [Hosted Login sign-out](../integrations/HostedLogin.md#7-sign-out-with-prepared-logout) |
| Redact sensitive values in the package's own logs, metrics, and traces | [DF-02..DF-11](../oidc/CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow) |

Out of scope in the first phase:

- Bearer API token validation for downstream resource services. Downstream services keep local
  JWKS-based validation of signature, issuer, audience, and lifetime, and accept that a
  self-contained access token stays valid to its own `exp`
  ([EV-03..05](../oidc/CanonicalSemanticModel.md#event--artifact--result),
  [caller responsibilities](../oidc/CanonicalSemanticModel.md#guarantees-and-caller-responsibilities)).
- Business authorization. The ID token carries no roles or permissions
  ([PS-12](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship)); every
  authorization decision stays with the consumer, expressed through the extension points below.
- Frontend concerns (views, assets, or SPA code).
- Refresh-token handling (`offline_access`), matching the first-phase Reference BFF shape with
  refresh disabled. Durable, revocable server-side tickets are the second phase tracked by
  [#479](https://github.com/philfanzhou/SignaCore/issues/479).

### Extension points

Consumers adapt the package only through four extension points; every other behavior is owned by
the package:

1. Administrator and authorization decisions — the consumer decides what an authenticated subject
   may do, typically by matching the verified `iss` plus `sub` against its own bindings.
2. Route prefix — where the package's endpoints are mounted (for example `/bff`).
3. Response format — bodies and status codes of the consumer-facing routes; the package defines
   protocol outcomes, not presentation.
4. Session and Bearer scheme selection — which of the consumer's routes authenticate against the
   package's session and which forward the stored access token as a Bearer credential.

### Versioning and release

- The package version equals the repository tag that produced it, and the package is published in
  the same release as the container image from that tag.
- `rc` tags publish prerelease packages only; stable tags publish stable packages.

### Compatibility promise

- Client `X.Y` supports SignaCore server `X.Y` and the immediately preceding minor `X.(Y-1)`; for
  `Y = 0` only `X.0` is supported. Combinations outside that range are not guaranteed.
- CI contract tests cover the promised matrix. The release pipeline that produces and tests the
  package is delivered by
  [#483](https://github.com/philfanzhou/SignaCore/issues/483) and is explicitly outside this ADR.

### Dependency policy

- The package depends only on ASP.NET Core and the `Microsoft.IdentityModel` family (for example
  `Microsoft.IdentityModel.JsonWebTokens`) for JWT and JWKS validation. No third-party
  authentication libraries are introduced.
- The package references no SignaCore server assembly. It consumes only the public HTTP contract:
  Discovery, the authorization endpoint, the token endpoint, JWKS, and `/oauth2/logout/requests`.

## Consequences

- The repository boundary rule gains exactly one sanctioned exception: the officially released
  client package. `AGENTS.md` and `CONTRIBUTING.md` now carry the amended rule, and the overview
  documents no longer state an unconditional assembly ban.
- A consuming service shrinks to its product-specific adaptation through the four extension
  points; protocol and security fixes propagate by updating one package.
- SignaCore takes on maintenance of the client package, its release discipline, and the promised
  compatibility matrix. A server change that would break the supported matrix now also breaks the
  package's contract tests rather than only external consumers.
- The server HTTP contract, Discovery metadata, and database schema are unchanged by this
  decision; downstream services that do not adopt the package are unaffected.
- The package is not a token-validation library. Downstream resource services keep local validation
  and keep accepting self-contained tokens to `exp`.
- Phase 1 ships without refresh-token handling in the package; consumers that need refresh tokens
  before the second phase keep their own implementation or keep refresh disabled.

## Alternatives considered

| Alternative | Reason rejected |
| --- | --- |
| Keep per-consumer implementations of the BFF protocol | The same protocol and security duties are re-derived, re-reviewed, and repeatedly fixed in every consumer; a SignaCore-side fix cannot reach them |
| Publish the server assemblies for downstream reference | It would couple consumers to internal schema, transport, and provider details and reopen the closed-boundary rule the exclusion protects |
| Build the package on a generic third-party OIDC client library | SignaCore's prepared logout, strict ID-token validation, session-expiry re-authentication, and redaction duties do not map onto a generic handler without re-deriving the same hardening; it would also violate the dependency policy |
| Revive the former client SDK | It predates the hosted-login contract and is no longer maintained; the official package starts from the ADR 0005 client duties |
| Include refresh-token handling in the first phase | It couples the first package slices to the durable, revocable ticket store of the second phase; the first-phase BFF shape runs with refresh disabled |
| Include downstream Bearer token validation in the package | Downstream resource services validate locally by design; a shared validator would blur the BFF package boundary and imply revocation semantics SignaCore does not offer |

## Standards basis

The package implements the client-side duties of the standards already followed by
[ADR 0005](./0005-interactive-oidc-confidential-bff.md): OpenID Connect Core 1.0, OpenID Connect
Discovery 1.0, [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636),
[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), and
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207). As on the server side, the prepared logout
transport is intentionally not a claim of RP-Initiated Logout 1.0 conformance.
