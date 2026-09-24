# Multi-Instance OIDC Acceptance

**Status: implemented acceptance surface.** This document describes how the two-instance acceptance
base is adapted for the OIDC interactive surfaces (`SignaCore` issue #102): which instance produces,
which consumes, how each shared dependency is disconnected for a negative self-check, and which
secret-free guarantees the tests pin. The two-instance base itself — one shared SQLite database and
bootstrap file, one `WebApplicationFactory<Program>` per instance, explicit A/B request addressing —
is owned by `MultiInstanceAcceptanceTests` (delivered with ServiceMantle #155) and is not duplicated
here.

## What crosses instances

| Surface | Canonical row | Producer | Consumer | Shared dependency |
| --- | --- | --- | --- | --- |
| Identity cookie drives the code flow | `PS-18` | Instance A's real login | Instance B's authorize endpoint | ServiceMantle Data Protection key ring + shared `identity_sessions` rows |
| Authorization continuation | `PS-03` | Instance A's authorize endpoint | Instance B's login endpoint (render, consume, redirect) | Shared `authorization_requests` rows (handle digest lookup, no cookie involved) |
| JWKS / issuance agreement | — | Instance A's token endpoint | Instance B's JWKS + a local `JwtSecurityTokenHandler` validation | Shared RSA key material through the database-backed key manager |

The two PS-03/PS-18 paths are verified separately: an unprotectable cookie says nothing about the
continuation row, and a recoverable continuation says nothing about the cookie. A test never treats
"the cookie unprotected" as proof that "the request record exists, is unexpired, and is unconsumed".

## Negative self-checks

Each shared dependency fails its own path, and the other paths keep working, so no green test rides
on an accidentally broken neighbor:

| Disconnect | Wiring in the test | Expected failure | Still-working proof |
| --- | --- | --- | --- |
| Authorization-request store | Instance B's `IAuthorizationRequestStore` replaced by an empty in-memory store | The login lookup answers the local generic error (`SC-18`); nothing about the stored snapshot — redirect URI, state — leaks; a cookie-less authorize fails closed with no handle and no code | B still unprotects A's identity cookie through the shared key ring |
| Wrong Data Protection purpose | The management cookie's payload carried in the identity cookie's name | The identity scheme is never satisfied; no code is issued (local 400 or the login fallback) | — |
| RSA key material | Instance B's `IKeyManager` replaced by an isolated in-process key ring | B's JWKS publishes a disjoint `kid` set; A's token fails signature validation against it | — |
| Data Protection key ring | Instance B is a deployment of its own: isolated database and bootstrap file | B cannot unprotect A's cookie; the real authorize flow falls back to the login continuation instead of issuing a code | B serves its own installation normally |

The purpose check complements `IdentitySessionCookieSharingTests`, which pins the raw
purpose-isolation unprotect behaviour; the acceptance here drives it through the real authorize
endpoint.

## Secret discipline

Across a full A-login → B-code → B-redemption run on captured logs: the login password, the
protected cookie payload, the access token, and the client secret never appear in any log line, and
both instances' JWKS responses carry public parameters only (`n`, `e` — never `d`, `p`, `q`). The
authorization code is not part of this log scan: it reaches the client inside the redirect Location
by protocol, and the MVC `RedirectResult` log line that echoes that Location is framework behavior;
the login flow's own log scan stays with `OAuthLoginSensitiveValueScanTests`.

## Out of scope

Full happy-path coverage, the complete attack matrix, and any second generic multi-instance or
Data Protection infrastructure. Real two-process Consul scenarios stay with the Consul acceptance
track; management-cookie crossing and the migration gate stay with `MultiInstanceAcceptanceTests`.
