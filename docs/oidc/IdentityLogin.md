# Identity Login and Continuation

**Status: target design.** Read the [directory boundary](./README.md) and the
[canonical model](./CanonicalSemanticModel.md) first.

Identity login proves which SignaCore account controls the browser. It does not grant permission to
administer SignaCore, authorize a downstream business action, or create an OIDC token by itself.
Only the Password credential establishes this browser identity in the first phase.

## Isolation from administration

Canonical `PS-18` and `PS-19` own the identity and antiforgery cookie contracts, including every
isolation rule between the identity cookie and the shared ServiceMantle management session (scheme
`ServiceMantle.ManagementCookie`, cookie `__Host-ServiceMantle.Management`). The management
session's issuance, logout, lifetime, and CSRF rules are owned by the ServiceMantle
management-session contract and are not restated here.

The target identity path uses a different authentication scheme, cookie name, Data Protection
purpose, authority record, and authorization policy. Its protected principal carries only the opaque
session identifier needed to load `PS-04`; account, credential, authentication time/method, activity,
and revocation authority remain in the database. Possessing either cookie never satisfies the other
policy. Creating, sliding, deleting, or revoking one never changes the other.

Because the shared package points every default authentication scheme at the management scheme,
`PS-18` requires each identity authentication, challenge, forbid, sign-in, sign-out, and identity
authorization policy to name the identity scheme explicitly; an identity path that omits the scheme
would issue or delete a management cookie. `PS-18` also fixes the isolation mechanism: both cookies
share the fixed ServiceMantle Data Protection application discriminator and the shared encrypted
key-ring store, so the identity scheme must not register a second application name and is separated
only by its own Data Protection purpose. That shared key ring still allows another SignaCore
instance to unprotect the identity cookie while keeping identity and administration cryptographically
and authoritatively distinct.

## Login inputs

The login page accepts no arbitrary destination. Canonical rows `IN-10` through `IN-15` own every
query/form field:

| Request | Fields | Canonical rows |
| --- | --- | --- |
| `GET /oauth2/login` | `login_handle` only | `IN-10` |
| `POST /oauth2/login` | `login_handle`, `username`, `password`, `__RequestVerificationToken`, `action` | `IN-11`–`IN-15` |

The POST is a bounded UTF-8 form. Handle/action/antiforgery validation precedes conditional
credential fields, so malformed structure and CSRF never invoke the Password validator or increment
failed-attempt state. `action=cancel` does not inspect username or password. `action=login` applies
the canonical username normalization and password opacity/length rules before reusing the existing
Password validator, shared lockout, account-status, audit, and metric chain.

Unknown account, wrong password, disabled account, and active lockout produce the same local
credential failure. This preserves the existing bounded failed-attempt behavior without turning the
new public login form into an account oracle.

## Server-side continuation

`PS-03` chose a shared server-side authorization request identified by a one-time digest-backed
handle. The login page receives no protected `returnUrl` or self-contained copy of the request. This
choice is load-bearing:

- an instance can continue a request created by another instance through shared state;
- expiry and consumption are explicit, rather than inferred from a protected blob;
- the browser cannot choose or tamper with a destination;
- missing, expired, and consumed handles follow `EV-03` without recovering stale redirect data.

The GET page renders no redirect URI, scope, state, nonce, challenge, or other stored request value.
It uses no-store/no-cache/no-referrer headers and denies framing. Passwords, handles, cookie values,
and antiforgery values follow `DF-01`, `DF-05`, and `DF-06` and never enter logs, audit details,
metrics, traces, exceptions, or error bodies.

## Successful login and current-policy revalidation

A successful password check is not permission to resume a stale request. Before any redirect,
SignaCore reloads the stored request and current client/account policy and reruns the canonical
client, exact redirect URI, scope, and account decisions. The original fact that those values were
valid cannot authorize a client that was disabled or a URI/scope that was removed while the form was
open.

`EV-01` defines the successful transaction: current policy is accepted, a fresh session identifier
is created, the continuation is consumed, the authorization result is created, and promised
login/audit writes commit together before the browser receives a response. An existing identity
cookie identifier is never reused. Cancellation follows `EV-02`: it revalidates the current client
and exact redirect URI, consumes the continuation only after they succeed, and otherwise returns a
local error. Invalid handles follow `EV-03`; credential failures follow `EV-17`; cancellation
observed around commit follows `EV-18`.

The routing result remains determined by the freshly validated client and URI. A client failure or
removed URI is local. A later protocol/policy failure uses the newly verified URI and canonical
error response. No path accepts `returnUrl`, a form-supplied URI, or an earlier unverified
destination.

## Test mapping

HTTP and security tests should use the canonical scenarios directly rather than copy their expected
state into this document:

| Test group | Canonical scenarios |
| --- | --- |
| Valid new-browser login and continuation | `SC-01` |
| Application, redirect, or scope changes while the form is open | `SC-02`–`SC-04` |
| Invalid CSRF versus valid but wrong credentials | `SC-19` |
| Cancellation before and after commit | `SC-20` |
| Independent concurrent authorization requests | `SC-07` |

Tests additionally assert the `PS-18`/`PS-19` cookie attributes and cross-scheme rejection, the
`IN-10`–`IN-15` field/error contract, no external redirect from an invalid handle, and the sensitive
boundaries above.

## Compatibility

This target document changes no current cookie, principal, Password grant, lockout row, shared
management session or management API (`PS-18`), Data Protection key material, or browser asset.
SMS, LDAP, and WeChat remain token-endpoint grants with no identity-login UI. Runtime work is
divided among #64–#66 and #94; documentation completion activates no route or Discovery metadata
(`AC-02`, `AC-05`, `AC-14`).
