# Tokens

**Status: target design.** See [README](./README.md).

Three token types, three different jobs. The ID token says who signed in and is consumed once by the
client. The access token authorizes calls and is consumed by downstream services. The refresh token
buys a longer session and is optional.

## ID token

RS256, signed by the same key ring as access tokens, discoverable through the existing JWKS
endpoint. `typ` is `JWT`.

| Claim | Presence | Value |
| --- | --- | --- |
| `iss` | Always | The configured issuer, identical to `issuer` in discovery and to `iss` in the authorization response |
| `sub` | Always | The account's stable identifier, as a string |
| `aud` | Always | The `client_id` of the requesting application, a single string |
| `exp` | Always | `iat` + 5 minutes |
| `iat` | Always | Issuance time, UTC seconds |
| `nonce` | Always | Copied byte-for-byte from the authorization request |
| `auth_time` | Always | When the identity session was established, UTC seconds |
| `sid` | Always | The identity session identifier |
| `amr` | Always | `["pwd"]` in this phase |
| `azp` | Never | Only meaningful with multiple audiences; there is exactly one |
| `name`, `nickname` | Only with `profile` | From the account record |
| `role`, `Permission`, `auth_method`, `client_id` | Never | These belong to the access token |

The ID token is an authentication statement, not an authorization one. It carries no role and no
permission, and a client MUST NOT make an access decision from it beyond "this is who signed in".

Five minutes is short on purpose. The token is consumed once, immediately, by a BFF that already has
it in hand; there is no reason for it to remain valid afterwards, and the short window makes the
`nonce` check a formality rather than the only replay defence.

`sub` is the account identifier: stable for the life of the account, never reused, and unchanged by
a username, phone number, or display-name change. `iss` + `sub` is the pair downstream services bind
their local administrator roles to. SignaCore makes no statement about what a subject may administer
anywhere; that is the downstream service's decision, recorded in its own store.

`amr` is `["pwd"]` because Password is the only credential that establishes an identity session. It
describes an authentication that happened, so it is honest today and stays honest if other
credentials are admitted later.

`acr` is **not** issued, and no placeholder value is reserved. An `acr` with a made-up value is a
security claim nobody can interpret, and a client that starts pattern-matching one would have to
unlearn it. See [README](./README.md) on unscheduled authentication strength.

### What the client must verify

Non-negotiable, and stated here because the acceptance criteria depend on it:

1. Signature, against a JWKS key selected by `kid`.
2. `iss` equals the expected issuer, exactly.
3. `aud` equals the client's own `client_id`, exactly.
4. `exp` is in the future and `iat` is not implausibly far in the past, with at most 120 seconds of
   clock skew.
5. `nonce` equals the value this client generated for this authorization request, and that value has
   not been accepted before.

A client that skips (3) accepts another application's token. One that skips (5) accepts a replay.

## Access token

Existing structure, existing pipeline, existing claims — `sub`, `name`, `role`, `nickname`,
`auth_method`, `client_id`, plus callback-injected `Permission` claims. `typ` is `at+jwt` (RFC 9068)
as it is today.

Two differences for interactive issuance:

| Property | Existing grants | Interactive |
| --- | --- | --- |
| `aud` | `AudienceMode` decides; `Shared` by default | Always the application's own AppId — `PerApplication` is required |
| Lifetime | `TokenExpirationHours`, default 2 hours | 15 minutes |

The lifetime difference is deliberate and is not a global change: existing grants keep their
configured lifetime exactly. An interactive access token lives in a BFF that can refresh silently
against a live identity session, so a short lifetime costs little, and it is the only bound on a
token that leaks — there is no revocation list for self-contained tokens.

15 minutes is the invariant for this phase, not a per-application setting. Making it configurable
means the first deployment under pressure sets it to two hours and the bound disappears.

## Refresh token

Opaque, existing format, existing storage (`RefreshTokenDigest`), existing rotation. Issued only
when both hold:

- The application has `allow_refresh_token = true`, and
- `offline_access` was in the granted scope.

Defaults are off. A BFF that keeps its own server-side session does not need one, and a refresh
token is a long-lived credential in a new place.

| Property | Value |
| --- | --- |
| Lifetime | `RefreshTokenExpirationDays`, default 7 days — unchanged |
| Rotation | On every use; the presented token is revoked as the new one is issued |
| Bound to | Account, application, and the identity session (`sid`) that produced it |
| Cross-application exchange | Not available. A token minted interactively MUST NOT be exchanged under [ADR 0003](../adr/0003-cross-application-refresh-grant.md) |
| Revoked by | `/oauth2/revoke`, logout, code replay, account disablement, application deactivation |

Barring interactive tokens from cross-application exchange keeps the two designs from composing into
something neither considered: the exchange grant assumes a token that stands for a service-to-service
relationship, while an interactive token stands for a browser session that can be revoked out from
under it.

### Reuse detection

Today's rotation is not reuse detection: replaying a consumed refresh token fails, but the token
minted from it stays valid. That gap is closed **within this phase**, for interactive clients, by the
refresh-family tasks (#70 → #97, #98).

| Property | Rule |
| --- | --- |
| Family | Every token records a family identifier, a root, and its parent. Rotation keeps the family and appends a child |
| Rotation | Atomic: concurrent rotation of one token yields at most one valid child |
| Reuse | Presenting a token already consumed revokes **every live descendant of that family**, not just the presented token |
| Binding | Family membership is bound to account, application, granted scope, and identity session |
| Scope | Interactive clients. The existing grants keep today's rotation semantics and today's wire contract |

So `allow_refresh_token` defaults to `false` for the reason stated above — a BFF with a server-side
session does not need a long-lived credential — and not because reuse would go undetected.

The family model and its migration are specified in [Persistence](./Persistence.md#refresh-token-families).

## Lifetime summary

| Artifact | Lifetime | Configurable |
| --- | --- | --- |
| Authorization code | 60 seconds | No |
| Continuation handle | 10 minutes | No |
| ID token | 5 minutes | No |
| Interactive access token | 15 minutes | No |
| Access token, existing grants | 2 hours (`TokenExpirationHours`) | Yes, unchanged |
| Refresh token | 7 days (`RefreshTokenExpirationDays`) | Yes, unchanged |
| Identity session, idle | 30 minutes sliding | Yes, deployment-wide |
| Identity session, absolute | 12 hours | Yes, deployment-wide |
| `identity_session_max_age` | Per application, capped by the absolute lifetime | Yes |

Configurable values live in `system_settings`, not `appsettings.json`. The invariants are invariant
because each one is a bound that a deployment under pressure would otherwise relax first.

## Revocation

`POST /oauth2/revoke` (RFC 7009) is unchanged: refresh tokens only, always HTTP 200 for a
syntactically valid request, only tokens belonging to the authenticated client. Revoking an
interactive refresh token does **not** end the identity session — the user is still signed in to
SignaCore, they have merely lost that application's offline access. Ending the session is what
[Logout](./Logout.md) is for.

Access tokens cannot be revoked. They are self-contained, there is no introspection endpoint in this
phase, and 15 minutes is the bound.
