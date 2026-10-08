# Transport Security Is a Deployment Decision

- Status: Accepted
- Date: 2026-10-08
- Decision owners: SignaCore maintainers
- Extends: [ADR 0002](./0002-database-backed-configuration.md)
- Scope decision record: [#566](https://github.com/philfanzhou/SignaCore/issues/566)

## Context

SignaCore inherited several code-level HTTPS-only transport rules: the registration and runtime
validation of redirect URIs refused plain `http` outside a Development loopback exception, the
hosted-login HTTP test-origin allowlist ([#519](https://github.com/philfanzhou/SignaCore/issues/519)
/ [#520](https://github.com/philfanzhou/SignaCore/issues/520) / [#521](https://github.com/philfanzhou/SignaCore/issues/521),
later [#564](https://github.com/philfanzhou/SignaCore/issues/564) for the client package) gated
plain-HTTP hosted login behind a `Testing` environment name and an explicit origin list, the issuer
had to be an absolute HTTPS URL unless `Security:AllowNonHttpsIssuer` was set, and outbound callback
requests required HTTPS by default (`Callback:RequireHttps`).

ServiceMantle's [#670](https://github.com/philfanzhou/ServiceMantle/issues/670) (v0.3.2) established
the opposite principle for the shared foundation: code keeps only structural URI rules — absolute
URI, no user info, no query or fragment, host and path shape — and never rejects by scheme. Whether
a deployment's traffic is TLS-protected is a property of the infrastructure in front of the service
(a reverse proxy, a TLS terminator, or a network partition), not of the application binary.

The two principles cannot coexist: every SignaCore-side scheme gate kept re-creating the friction
the shared foundation removed (each private-network deployment needed a new opt-in), and each
opt-in added configuration surface that itself needed testing, recovery semantics, and
documentation.

## Decision

SignaCore removes every code-level transport policy for its own HTTP surfaces. Scheme policy exits
the code on both ends:

1. **Redirect and post-logout URIs** (registration, bootstrap pre-seed, management API, authorize,
   token redemption, logout): `http` and `https` are accepted equally in every environment, with no
   Development loopback privilege, no allowlist, and no opt-in. The structural rules are unchanged
   and remain enforced: absolute URI, `http`/`https` scheme only, no user info, no wildcard,
   no fragment, canonical host form, exact-registration matching, the per-kind count limit, and the
   refusal of the `localhost` host name (a browser resolves it locally, so it names no deployment
   authority).
2. **Public base URL and issuer**: both schemes are accepted; the issuer must be an absolute
   `http` or `https` URL and must equal the public base URL. `Security:AllowNonHttpsIssuer` and the
   shared key `security.allow_non_https_issuer` are retired.
3. **Hosted-login cookies**: the identity and CSRF carriers are derived from the request scheme
   alone — `https` rides the Secure `__Host-`-prefixed carriers, plain `http` rides neutral
   non-Secure carriers. The derived name must still satisfy every browser rule its prefix implies;
   configuring a prefixed cookie name while actually serving plain http fails fast at startup. The
   `security.hosted_login_http_test_origins` key, its `Testing` environment gate, and the
   public-base-URL origin-membership check are retired.
4. **Outbound callbacks**: `Callback:RequireHttps` now defaults to `false`. The SSRF gates —
   `Callback:AllowedDomains` and `Callback:AllowPrivateAddresses` — are unchanged and carry the
   real protection.
5. **The official client package** (`SignaCore.Client.AspNetCore`) follows the same principle for
   Authority/RedirectUri validation and its own cookie derivation; its `IntranetHttpOrigins`
   opt-in is retired (see the package README). This ADR covers both ends; the package-side tasks
   are tracked in [#566](https://github.com/philfanzhou/SignaCore/issues/566).

Retired shared keys keep their stored rows ignored by every read (a leftover row never blocks
startup, management queries, or updates); dropping the rows after an upgrade is optional
housekeeping documented in the upgrade notes.

## Consequences

- A plain-HTTP deployment — an intranet, a container network, or a developer machine — works
  end-to-end (registration, authorize, hosted login, callback, token, JWKS, logout, and the client
  package) with zero extra configuration in any environment name.
- The guarantees SignaCore itself provides are unchanged where they do not depend on transport:
  PKCE S256, state/nonce, single-use authorization codes, exact redirect matching, issuer/audience
  validation, JWKS key rotation, refresh-token rotation, and CSRF boundaries.
- Confidentiality, integrity, and listener authenticity on a plain-HTTP link are **not** provided
  by the code. Deployments that need TLS must terminate it in front of the service; the
  documentation keeps its recommendation to use TLS for public deployments. This is a deliberate
  deviation from RFC 9700's https assumption for private-network deployments, accepted here as the
  price of removing the endless opt-in surface.
- Cookie carriers follow the request scheme, so a TLS-terminating proxy must forward the effective
  scheme (`X-Forwarded-Proto` with the existing trusted-proxy configuration) for the Secure
  carriers to be selected.
- The rollback story is symmetric: reverting the change restores the scheme gates; stored rows of
  the retired keys are ignored (newer binary) or must be deleted before running an older binary
  that does not know them, exactly like every previous key retirement.
