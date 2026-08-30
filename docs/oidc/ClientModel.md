# Interactive Client Model

**Status: target design.** Read the [directory boundary](./README.md) and the
[canonical model](./CanonicalSemanticModel.md) first.

An existing SignaCore application remains the unit of registration. Interactive OIDC is an
explicit, disabled-by-default capability on that application; it does not create a parallel client
store or reinterpret an existing field. Canonical rows `PS-01`, `PS-02`, `PS-20`, and `PS-21`
define the complete configuration and URI contract.

## A claims callback is not a redirect URI

The two values can point at the same deployment by coincidence, but they have unrelated authority:

| Property | Claims callback | Redirect or post-logout URI |
| --- | --- | --- |
| Direction | SignaCore server to application server | SignaCore sends the browser to the application |
| Purpose | Fetch application-owned business claims during access-token issuance | Deliver an authorization or prepared-logout result |
| Request influence | Never selected by an authorization request | Named by an untrusted browser request and therefore revalidated |
| Validation | Existing callback registration and outbound-request controls | Canonical URI registration and exact request comparison in `PS-20` |
| Failure boundary | Existing issuance fallback remains unchanged | An unverified URI is never a redirect destination |

Consequently, implementation and administration must never copy, migrate, prefill, suggest, or
write `callback_url` as a redirect URI, or write a redirect URI back into `callback_url`. Existing
applications gain no redirect registration on upgrade. This follows `PS-02`; later storage and UI
tasks must preserve the separation in their schema, DTOs, labels, and tests.

## Client policy

`PS-21` owns defaults, allowed values, and invariants. The implementation-facing mapping is:

| Policy field | Canonical owner | Implementation consequence |
| --- | --- | --- |
| `allow_authorization_code` | `PS-01`, `PS-21` | Gates browser authorization and code redemption; old applications remain fail closed |
| `client_type` | `PS-21` | Only confidential clients are actionable in this phase; public is reserved fail-closed data |
| `allowed_scopes` | `PS-21`, `IN-04` | Closed set with canonical ordering; request validation never invents or silently narrows scope |
| `allow_refresh_token` | `PS-21`, `EV-11` | Controls whether `offline_access` can be configured and what a later state change does |
| Redirect URI sets | `PS-02`, `PS-20` | Independent ordered registrations, never derived from the claims callback |
| `identity_session_max_age` | `PS-01`, `PS-21` | Optional application cap, bounded by the global absolute identity-session lifetime |
| `audience_mode` | `PS-01`, `PS-21` | Interactive code flow requires the existing `PerApplication` access-token audience mode |

PKCE S256, `response_type=code`, query response mode, mandatory `state` and `nonce`, and the absence
of consent are protocol invariants rather than switches. Making them configurable would turn an
administrative edit into a security downgrade.

Enabling code flow on a shared-audience application fails instead of silently changing its audience.
The existing audience migration remains deliberate: teach the downstream resource service to accept
both audiences, switch the application to `PerApplication`, remove the shared audience there, and
only then enable interactive authorization. None of those steps changes tokens already issued by an
existing grant.

## Redirect URI registration and comparison

`PS-20` is the normative registration algorithm for both redirect kinds. Registration parses and
stores one canonical string; an authorization, token, or logout request is never normalized and is
compared to the relevant stored value with ordinal equality. Parsing request input again would make
the comparison depend on URI-library equivalence rather than the administrator's exact registration.

These non-normative examples illustrate one registration:

| Requested value when `https://orders.example/signin-oidc` is registered | Result |
| --- | --- |
| `https://orders.example/signin-oidc` | Exact match |
| `https://orders.example/signin-oidc/` | No match: trailing slash differs |
| `https://orders.example/Signin-Oidc` | No match: path case differs |
| `https://orders.example:443/signin-oidc` | No match: requests are not normalized |
| `https://orders.example/signin-oidc?source=one` | No match: query differs |
| `https://orders.example.attacker.test/signin-oidc` | No match: authority differs |

The Development-only loopback exception in `PS-20` applies to a registered BFF callback, not to a
claims callback and not to a wildcard. `localhost`, fragments, userinfo, and patterns remain invalid.

## Scopes and configuration changes

`IN-04` defines request syntax and `PS-21` defines policy. A requested member outside the current
allow list is `invalid_scope`; SignaCore does not delete that member and continue. `EV-11` and
`EV-13` own later effects when refresh permission or a scope is removed. This document adds no
alternative downgrade behavior.

The application-management implementation is split deliberately:

- #61 owns persistence and reusable domain validation.
- #62 owns management API and optional bootstrap mapping.
- #63 owns the administrative console.

All three consume the same canonical rules. Their intermediate completion activates no Discovery
metadata (`AC-01`).

## Compatibility

Today, `app_registrations` contains the existing application identity, secret hash, claims callback,
admission policies, active state, and audience mode. This target design changes none of those facts
by documentation alone. Existing applications, grants, callbacks, shared-audience tokens,
`bootstrap-apps.json`, and admin API responses retain their current behavior until their focused
implementation tasks explicitly add disabled-by-default fields and provider-symmetric migrations.
