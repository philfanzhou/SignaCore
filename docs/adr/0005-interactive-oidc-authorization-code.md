# ADR 0005: Interactive OIDC Authorization Code for First-party Confidential BFFs

- Status: Accepted
- Date: 2026-08-30

## Context

SignaCore authenticates people and issues RS256 access tokens, but every existing grant takes a
credential directly: `password`, `sms`, `ldap`, `wechat_code`, `refresh_token`. There is no
authorization endpoint, no authorization code, no PKCE, no `id_token`, no UserInfo endpoint, and no
browser identity session that belongs to the identity service rather than to its own admin console.
`DiscoveryDocument` is honest about this — `response_types_supported` is empty — and
[StandardsConformance](../overview/StandardsConformance.md) records the gaps.

The consequence is concrete. When another service's admin console wants SignaCore to authenticate
its administrators, the only options are: hand the administrator's password to that service, call
the token endpoint from its browser front end, keep a second local administrator password store, or
adopt a different identity provider. The first three all put a high-privilege credential somewhere
it does not belong.

Closing that gap is not one change. It is a client model, a redirect-based endpoint, a browser
session, a new short-lived shared secret (the authorization code), a second token type, a profile
endpoint, a logout surface, and the invalidation rules that tie them together — spread over roughly
a dozen implementation tasks in two migration histories. Every one of those tasks has to agree on
field names, lengths, comparison rules, lifetimes, error codes, and which errors may be reflected
back to a browser. Deciding those per pull request guarantees they will be decided differently, and
each disagreement is either a compatibility break or a security hole.

This ADR fixes the decisions. The field-level contracts they imply are written out in
[docs/oidc](../oidc/README.md); this record explains what was chosen and why, and what was rejected.

The existing facts that constrain the answer:

1. **`app_registrations.CallbackUrl` is not a redirect URI.** The callback is an endpoint SignaCore
   *calls* during issuance to collect an application's claims for an account. A redirect URI is a
   place SignaCore *sends the browser*. They differ in direction, in trust, in matching rules, and
   in blast radius: a wrong callback leaks claims to one server, a wrong redirect URI hands an
   authorization code to an attacker.
2. **Access-token audience defaults to `Shared`.** Under `AudienceMode.Shared` a token issued to one
   application validates at every other one. That default exists for compatibility with deployments
   that predate `PerApplication`; it is the opposite of what an interactive administrative client
   needs.
3. **The admin console already owns a cookie.** `qz_admin_session` means "this person may administer
   SignaCore itself". An identity session means "this person proved who they are". Conflating them
   would make every account that can log in a candidate SignaCore administrator.
4. **Refresh tokens rotate but do not detect reuse.** Today a replayed refresh token fails while its
   descendants survive. An interactive flow that hands refresh tokens to a browser's back end widens
   the window in which that matters, so this phase closes the gap for interactive clients with a
   refresh-token family model rather than inheriting it.
5. **SQLite is a supported provider.** Authorization codes are one-shot shared state. On PostgreSQL
   they are consumed atomically across instances; on SQLite there is exactly one instance and the
   guarantee comes from there being one writer.

## Decision

Deliver OIDC Authorization Code with mandatory S256 PKCE for **pre-registered, first-party
confidential BFFs**, and fix the following baseline for every task under that epic.

### Client model

Interactive capability is opt-in per application and stored separately from the callback
configuration. `response_type` is `code` and nothing else. Redirect URIs are a registered set,
compared by exact string equality after registration-time normalization, with no wildcard, prefix,
or path-suffix matching, and are never derived from `CallbackUrl`. Migrating or reinterpreting an
existing `CallbackUrl` as a redirect URI is prohibited — including as a convenience default in an
administration UI.

An application that enables the authorization-code flow must use `AudienceMode.PerApplication`.
Interactive clients are the one place where the compatibility default is not offered: a new
administrative console has no legacy validators to keep working, and a shared audience would make
one console's token accepted by all of them.

### PKCE is an invariant, not a policy

Every authorization-code request carries `code_challenge` with `code_challenge_method=S256`. There
is no `require_pkce` toggle and no `plain` support, because a per-client switch is a downgrade
waiting to be flipped and `plain` gives an attacker who can read the authorization request
everything needed to redeem the code.

### One identity session, isolated from administration

A new cookie scheme, cookie name, and Data Protection purpose carry a **SignaCore identity
session**. It is not `qz_admin_session`, cannot authenticate `/api/admin/*`, and carries no
administrative claim. The administrative cookie is likewise not accepted at the authorization
endpoint or the identity login pages. Only the Password credential may establish an identity session
in this phase; SMS, LDAP, and WeChat keep working as token-endpoint grants and gain no browser
surface.

The session record lives in the shared database so it can be revoked from any instance, and the
cookie carries only its identifier. Sliding idle expiry plus a hard absolute lifetime; logout,
account disablement, and administrative revocation all end it on every instance.

### Authorization codes are short-lived digests consumed atomically

A code is 32 CSPRNG bytes, base64url-encoded, returned once and stored only as a versioned SHA-256
digest — the representation already used for refresh tokens. Sixty seconds of validity. Redemption
is a single conditional update that both marks consumption and returns the row, so two concurrent
redemptions cannot both succeed. Redeeming a code that was already consumed is treated as an attack:
it fails with `invalid_grant` and revokes the refresh token that the first redemption produced.

### Errors split into two classes

Before the client and its redirect URI are both verified, nothing is redirected anywhere: the
browser stays on a SignaCore error page. After they are verified, protocol errors go back to the
verified redirect URI as `error`/`error_description`/`state`/`iss`. Getting this backwards in either
direction is a vulnerability — redirecting on an unverified URI is an open redirect that also leaks
the failure, and rendering a locally-handled error for a verified client turns a recoverable
protocol error into a dead end.

Authorization responses use query response mode and always carry `iss` (RFC 9207), so a client that
talks to more than one issuer cannot be induced to redeem a code at the wrong one.

### Scopes are a fixed, per-application allow list

`openid` is required. `profile` and `offline_access` are optional and must be in the application's
allow list. Anything else is `invalid_scope`. A refresh token is issued only when the application
allows it *and* `offline_access` was granted — the default for a new interactive client is no
refresh token, because a BFF holding a server-side session does not need one.

`sub` is the account identifier, stable for the life of the account and never reused. Downstream
services key their local administrator bindings on `issuer + subject`, and SignaCore makes no
statement about what a subject may administer anywhere.

### Nothing existing changes

The `password`, `sms`, `ldap`, `wechat_code`, and `refresh_token` grants, the legacy `/api/auth/*`
wire contract, the callback mechanism, `AudienceMode.Shared` for existing applications, and
`qz_admin_session` all keep their current behaviour. The new capability is additive; every migration
in the series adds tables and columns and changes none.

### Discovery advertises only what has shipped

`DiscoveryDocument` gains each field in the pull request that makes the corresponding capability
real, never earlier. Documentation in this repository may describe the target design, but it must
label it as target, and the running service must not claim to be an OpenID Provider until an
`id_token` is actually issued.

### Common infrastructure is consumed, not rebuilt

Data Protection key storage, structured-log scrubbing, the Serilog host, OpenTelemetry, Prometheus,
sensitive-header handling, and the shared dual-instance PostgreSQL acceptance base come from
ServiceMantle. SignaCore owns the protocol, the product events, the business metrics, and the
OIDC-specific rate-limit partitions. The full split is in [Ownership](../oidc/Ownership.md).

## Consequences

- Twelve or so implementation tasks now share one vocabulary and one error matrix, and the matrices
  in [docs/oidc](../oidc/README.md) are written so each row becomes a test.
- This decision alone ships no runtime capability. Until the endpoint tasks merge, SignaCore remains
  an OAuth 2.0 authorization server that is not an OpenID Provider, and discovery keeps saying so.
- Both migration histories gain the same set of additive tables. A deployment that never registers
  an interactive client carries empty tables and behaves exactly as before.
- SQLite deployments get the full flow but remain single-instance. That is not a new restriction,
  but authorization codes make the reason sharper: a second SQLite writer would break atomic
  redemption, not merely slow it down.
- Requiring `PerApplication` for interactive clients means an operator cannot point an existing
  shared-audience application at the new flow without first migrating its downstream validators.
  That is deliberate friction on the exact step where a mistake grants one console's token to every
  console.
- Restricting identity sessions to the Password credential means an administrator who signs in to
  other applications by SMS cannot yet use a redirect-based login. Widening it is a later decision
  with its own admission and audit questions, not an omission to be fixed in passing.
- Access tokens issued interactively are short-lived (minutes, not hours). Downstream services that
  cache a validated token for the life of a page will notice. This is the point: the shorter
  lifetime is what bounds the damage of a token that leaks out of a BFF.

## Alternatives considered

- **Reusing `CallbackUrl` as the redirect URI.** Rejected. Every registered application already has
  one, so enabling the flow would silently authorize an existing URL as a code destination. The two
  fields also have incompatible matching rules — a callback is dialled by SignaCore and may be any
  reachable endpoint, while a redirect URI is attacker-influenced input that must match exactly.
- **A single browser cookie for both identity and SignaCore administration.** Rejected. It is one
  cookie fewer and one privilege boundary fewer. The admin cookie's authority would then follow
  every account that authenticates for any application, and revoking administration would mean
  revoking authentication.
- **Making PKCE and `S256` per-client policy.** Rejected. The only clients that would ever want it
  off are the ones that cannot implement it, and admitting them is the downgrade the attack model is
  about. A confidential BFF can always compute SHA-256.
- **Keeping `AudienceMode.Shared` available to interactive clients.** Rejected as the default and as
  an option. The whole point of per-console authentication is that a token minted for one console is
  refused by the next.
- **In-memory or instance-local authorization codes.** Rejected. Behind a load balancer the
  redemption lands on a different instance than the authorization request, so the flow would fail
  intermittently in exactly the deployment shape this feature targets. Correct behaviour would then
  depend on sticky sessions, which is an operational assumption the protocol should not make.
- **Encrypting the authorization code so it can be self-contained and stateless.** Rejected.
  Single-use is the property that matters most, and a self-contained code cannot be consumed — it
  needs a server-side record to mark, at which point the record may as well be the code's home.
- **Delivering OAuth authorization code first and adding OIDC later.** Rejected. The consumer is an
  administrative console that needs an authenticated subject, not an access token; without
  `id_token` and `nonce` the first integration would invent its own identity claim and then have to
  unlearn it. The two-step delivery also means the browser flow ships once without replay protection
  on the identity assertion.
- **Issuing refresh tokens to interactive clients by default.** Rejected. A BFF already keeps
  server-side state; the refresh token buys a longer session at the cost of a long-lived credential
  in a new place. Applications that genuinely need one enable `offline_access` explicitly. The
  default is off because the credential is unnecessary, not because its reuse would go undetected —
  interactive refresh tokens get a family model with reuse detection in this same phase.
- **A consent screen in this phase.** Rejected. Every client is first-party and pre-registered by an
  administrator, so consent would ask a question whose answer is already recorded, and the screen is
  another redirect surface to secure. It becomes necessary the moment third-party clients do, and
  that is a separate decision.
