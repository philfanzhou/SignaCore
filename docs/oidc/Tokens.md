# Interactive ID and Access Tokens

**Status: target design.** Read the [directory boundary](./README.md), the
[canonical model](./CanonicalSemanticModel.md), and
[authorization-code redemption](./TokenEndpoint.md) first.

An ID token tells the confidential BFF which SignaCore subject authenticated. An access token
authorizes a downstream resource service. They are independently constructed signed JWTs with
different types, consumers, claims, lifetimes, and validation duties; a valid token of one kind can
never substitute for the other.

## ID token

`PS-12` owns the complete schema. Its implementation-facing claim projection is:

| Header or claim | Initial code exchange value |
| --- | --- |
| `alg`, `kid`, `typ` | Exactly `RS256`, current signing-key id, and `JWT` |
| `iss` | Configured issuer, exactly matching Discovery and the authorization response issuer |
| `sub` | Stable account id rendered as a string; username/profile edits never change it |
| `aud` | One string: the confidential client's `client_id` |
| `iat`, `exp` | Captured UTC issue time and exactly five minutes later |
| `auth_time` | Original identity-session authentication time, not token issue time |
| `sid` | Original identity-session id |
| `amr` | JSON array containing only `pwd` in this phase |
| `nonce` | Exact authorization-request snapshot, present on the first ID token only |
| `name` | Bound Password username only when `profile` was granted |
| `nickname` | Current non-null account nickname only when `profile` was granted |

`azp`, `acr`, role, permission, `auth_method`, `client_id`, callback claims, and access-token binding
claims are absent. Callback output cannot replace a core claim or inject a second copy. The ID token
contains an authentication statement, not downstream authorization; consumers must never treat its
profile fields as roles or permissions.

The BFF validates the RS256 signature through the `kid` selected JWKS key, exact issuer, its own
audience, lifetime, and exact one-time nonce. It also validates the authorization response `iss`
before token exchange and binds state, nonce, and verifier to its own server-side browser session.
Unexpected additional audiences, a missing/mismatched nonce, or a token whose type/purpose is not an
ID token fails closed. SignaCore fails issuance before commit if the serialized ID token exceeds
8192 ASCII characters. The BFF derives its local subject key from issuer plus subject and owns every
downstream authorization decision.

## Interactive access token

`PS-13` owns this schema. Its header is exactly `alg: RS256`, the current `kid`, and
`typ: at+jwt`. The claims are:

| Claim group | Interactive value |
| --- | --- |
| JWT authority | Configured `iss`; application AppId `aud`; 15-minute `exp`; captured `nbf`/`iat`; unique `jti` |
| Subject and client binding | Stable account-id `sub`, `client_id`, and identity-session `sid` |
| Authentication | Existing `auth_method`, carrying the Password method captured by the identity session |
| Granted authority | Canonical space-delimited `scope`, byte-for-byte equal to the token response |
| Existing basic/business claims | Existing name/nickname/role/`Permission` behavior plus callback enrichment, subject to reserved-claim protection |

Interactive code flow requires `PerApplication`, so the access-token audience is always the
application AppId. That value happens to equal the ID-token client audience in the first phase, but
the meanings are different: the ID token is for the BFF as relying party; the access token is for
the application-owned resource service. Neither audience can fall back to the deployment-wide
shared value.

`scope` is in canonical `openid profile offline_access` order with absent members omitted. `sid`
identifies the live authority UserInfo will later check. It does not make the self-contained access
token revocable: account, application, session, or scope changes leave a previously issued token
valid to `exp` at downstream resource services. Those services validate `typ`, signature, issuer,
their own audience, and lifetime; they do not query SignaCore state.

Callback and bootstrap-role enrichment remain available for the interactive access token, but the
issuer, subject, audience, time, `jti`, client, scope, session, or token-type binding cannot be
removed, replaced, or duplicated by external claims. Serialized output over 8192 ASCII characters
fails issuance before commit.

## Separation summary

| Property | ID token | Interactive access token |
| --- | --- | --- |
| Consumer | Confidential BFF | Application-owned resource service and later UserInfo |
| Purpose | Authenticate a subject to the BFF | Authorize resource access |
| JOSE `typ` | `JWT` | `at+jwt` |
| Audience meaning | Client identifier | Resource/application identifier |
| Lifetime | 5 minutes | 15 minutes |
| `nonce` | Exact initial request nonce | Never |
| `scope`, `sid` | `sid` only | Both canonical scope and `sid` |
| Role/permission/callback claims | Never | Existing enrichment allowed |
| Live-state revocation | Not revocable; valid to `exp` | Not revocable downstream; valid to `exp` |

Both use the existing database-backed signing authority in `PS-10`, but separate constructors and
reserved-claim policies prevent type confusion. `PS-09` persists no token row. Token bytes remain
request-local, are never logged, and are released only after the issuance transaction commits.
Signing-key rotation follows `EV-16`/`SC-17`: new tokens use the new `kid`, while still-needed public
keys remain in JWKS for previously issued tokens.

## Code-exchange response

`PS-14` owns the JSON result. Every successful code exchange contains `access_token`,
`token_type: Bearer`, `expires_in: 900`, `id_token`, and the canonical granted `scope`. A
`refresh_token` appears only when `offline_access` was granted and the optional family root committed
in the same transaction. The response has `Cache-Control: no-store` and `Pragma: no-cache` and is
not exposed before the state described by `EV-20` or `EV-21` commits.

The `scope` value is always present; it reports the authorization snapshot rather than accepting a
token-request override. The initial ID token always carries the stored nonce because `openid` is
mandatory. Refresh response construction, nonce omission on refresh, family rotation, and reuse
handling belong to #133 and are not redefined here.

## Verification mapping

Tests project canonical scenarios rather than inventing another result matrix:

| Test concern | Canonical owner |
| --- | --- |
| Successful initial issue with or without an optional family | `EV-20`, `EV-21`, `SC-01` |
| ID/access claim, audience, type, lifetime, nonce, scope, and session separation | `PS-12`–`PS-14` |
| Exact family association or null on later code replay | `SC-07`, `SC-08`, `SC-09` |
| Session/scope/application rejection before issue | `SC-10`, `SC-11`, `SC-12` |
| Double redemption produces no second token set | `SC-13` |
| Signing failure exposes no token and leaves code redeemable | `SC-16` |
| Signing rotation preserves validation continuity | `SC-17` |
| Cancellation before versus after commit | `SC-20` |

Tests also prove that an ID token is rejected as an access token, an access token is rejected as an
ID token, reserved claims cannot be replaced by callback data, oversized output rolls back, and no
token or private-key material enters persistence or diagnostics.

## Existing-grant compatibility

Password, SMS, LDAP, WeChat, legacy Refresh, and cross-application exchange keep their current
access-token constructor, configured lifetime, `AudienceMode`, claims, callback behavior, and wire
responses. They gain no interactive `scope` or `sid`, and `/api/auth/token` gains no `id_token` or
`scope`. Shared-audience applications stay shared and cannot enable code flow without the explicit
migration described in [Client Model](./ClientModel.md).

Current Discovery continues to describe the runtime as an OAuth authorization server with no
authorization response type or ID token. Only the complete #54 slice may advertise the core flow
under `AC-07`; this document itself has no metadata effect (`AC-14`).
