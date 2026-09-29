# Identity Login and Continuation

**Status: target design.** Read the [directory boundary](./README.md) and the
[canonical model](./CanonicalSemanticModel.md) first.

Identity login proves which SignaCore account controls the browser. It does not grant permission to
administer SignaCore, authorize a downstream business action, or create an OIDC token by itself.
The Password credential establishes this browser identity today. The target design adds an SMS
one-time code as the second and only other credential; see
[SMS one-time-code login](#sms-one-time-code-login) and the activation stages `AC-15`–`AC-17`.

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
| `POST /oauth2/login` | `login_handle`, `username`, `password`, `__RequestVerificationToken`, `action`; from `AC-17` also `phone` and `otp` for `action=sms_login` | `IN-11`–`IN-15`, `IN-17`–`IN-19` |
| `POST /oauth2/login/sms-code` (target, from `AC-16`) | `login_handle`, `__RequestVerificationToken`, `phone`, `otp` (ignored) | `IN-16`, `IN-17`, `IN-19` |

The POST is a bounded UTF-8 form. Handle/action/antiforgery validation precedes conditional
credential fields, so malformed structure and CSRF never invoke the Password validator or increment
failed-attempt state. `action=cancel` does not inspect username or password. The Cancel button
carries `formnovalidate`, so a browser submits the cancel without client-side validation of the
required credential fields. `action=login` applies the canonical username normalization and
password opacity/length rules before reusing the existing Password validator, shared lockout,
account-status, audit, and metric chain.

Unknown account, wrong password, disabled account, and active lockout produce the same local
credential failure. This preserves the existing bounded failed-attempt behavior without turning the
new public login form into an account oracle.

## SMS one-time-code login

**Status: target design; not active until `AC-16` (send route) and `AC-17` (SMS login and page
region).** This section explains the canonical rows and does not restate them.

The application comes only from the stored continuation, and its current SMS policy decides every
result exactly as the SMS grant does: the `IN-19` gate (`SmsLoginMode` not `Disabled` and an SMS
profile configured) decides whether the page shows an SMS form at all, send eligibility decides
whether a code is actually sent, and the `PS-04` SMS admission predicate decides whether an `Sms`
session is usable for an application. `AutoProvision` can create an account only inside the
successful login transaction (`EV-36`), never from a send.

Sending a code is a separate route rather than another `action` value, because rate-limit policies
apply per endpoint and the partition resolver never reads a login body. The route is bounded by
three budgets: the per-continuation count stored on the continuation row (`PS-03`), the
`oidc-sms-code` source-network policy (`PS-24`), and the existing per-phone OTP windows. Every send
that passes the request-shape checks returns the uniform result listed under
[browser SMS send eligibility and uniform results](./CanonicalSemanticModel.md#browser-sms-send-eligibility-and-uniform-results);
an invalid phone format is the only other 200 answer and depends only on the typed value. Every SMS
login failure returns the generic SMS failure of `EV-37`, and the Password failed-attempt counter
is never touched by the SMS path.

The uniform result has a user-experience cost that integrators should explain to their users: a
phone that cannot sign in to the application still sees a notice that a code may have been sent.
Response timing is explicitly not uniform; the budgets above bound how fast it can be probed.

Phone numbers and codes follow `DF-16` and `DF-17`: the phone appears in audit rows only in masked
form and never in a URL, cookie, token, UserInfo response, metric label, or trace; the code is never
echoed or stored in plaintext. The page stays script-free: the SMS form's send button posts to the
send route through `formaction`, which `form-action 'self'` already admits.

A session created by SMS login records the auth method `Sms` and the SMS identity (`PS-04`). Reusing
it for another application, redeeming a code, refreshing, and calling UserInfo all recheck that
application's current SMS admission; a failure behaves as `EV-38`. ID tokens carry `amr: ["sms"]`
(`PS-12`).

## Server-side continuation

`PS-03` chose a shared server-side authorization request identified by a one-time digest-backed
handle. The login page receives no protected `returnUrl` or self-contained copy of the request. This
choice is load-bearing:

- an instance can continue a request created by another instance through shared state;
- expiry and consumption are explicit, rather than inferred from a protected blob;
- the browser cannot choose or tamper with a destination;
- missing, expired, and consumed handles follow `EV-03` without recovering stale redirect data.

The GET page renders no redirect URI, scope, state, nonce, challenge, or other stored request value.
It uses no-store/no-cache/no-referrer headers and denies framing. A rendered login form (the GET page
and the credential-failure re-render) sends
`Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self' <origin>; frame-ancestors 'none'; base-uri 'none'`,
where `<origin>` is the `scheme://host[:port]` origin of the request's stored, exactly matched
redirect URI. Browsers enforce the submitting page's `form-action` across the redirect chain of the
submission, so without that origin the cancel and success redirects to a callback on another origin
would be blocked. The origin is derived only from the stored redirect URI, never from request input,
and the header carries no path, query, state, or other stored value. A redirect URI whose origin
cannot be expressed as a CSP host-source (for example an IPv6 literal such as `http://[::1]:5173`)
keeps `form-action 'self'`; use `127.0.0.1` for local development callbacks. Every other
`/oauth2/login` response, including local errors and the cancel and success redirects, sends
`default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`. The policy is not redirect validation: the exact redirect URI checks and
revalidation remain the only authority for where a browser is sent. Passwords, handles, cookie values,
and antiforgery values follow `DF-01`, `DF-05`, and `DF-06` and never enter logs, audit details,
metrics, traces, exceptions, or error bodies.

## Page language and style

The login page, the credential-failure re-render, and the local error page are rendered in
Simplified Chinese (`zh-CN`) or English (`en`). The language comes only from the `Accept-Language`
request header: the header is parsed strictly, ranges are ordered by quality (header order breaks
ties) and `q=0` ranges are skipped, the first `zh` or `zh-*` range selects `zh-CN`, and the first
`en`, `en-*`, or `*` range selects English. A missing header, a header that fails strict parsing, a
quality outside 0–1, or a header without a matching range selects English. No query or form field,
cookie, stored continuation value, or configuration key selects the language, and `ui_locales` is
not supported. `<html lang>` carries the selected language, and every HTML response of the route
sends `Vary: Accept-Language`.

Only the visible text changes with the language. Field names, their order, hidden fields, button
names and values, error routing, and the security headers are identical in both languages. Within
one language, every local rejection still returns the same bytes and every credential failure the
same page (`SC-19`); neither language echoes a submitted value. API, log, audit, and exception text
stays English.

The page stays script-free. It links one same-origin stylesheet, `GET /oauth2/login/style.css`,
admitted by `style-src 'self'`. The stylesheet is a fixed constant served with
`Content-Type: text/css; charset=utf-8`, `Cache-Control: public, max-age=3600`, and
`X-Content-Type-Options: nosniff`. The route needs no identity or management authentication, reads
no query, body, cookie, or header, writes no cookie, has no OIDC rate-limit policy (the host-wide
limit still applies), and loads no font, image, or other resource.

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
| SMS login, admission, provisioning, reuse, abuse, and races (target) | `SC-21`–`SC-26` |

Tests additionally assert the `PS-18`/`PS-19` cookie attributes and cross-scheme rejection, the
`IN-10`–`IN-15` field/error contract, no external redirect from an invalid handle, and the sensitive
boundaries above.

## Compatibility

This target document changes no current cookie, principal, Password grant, lockout row, shared
management session or management API (`PS-18`), or Data Protection key material. The only browser
asset is the login stylesheet described above.
LDAP and WeChat remain token-endpoint grants with no identity-login UI. The SMS token grants and
`POST /api/auth/sms-code` keep their current behavior; browser SMS login activates only through
#443–#445 (`AC-15`–`AC-17`). Runtime work for the Password login is divided among #64–#66 and #94;
documentation completion activates no route or Discovery metadata (`AC-02`, `AC-05`, `AC-14`).
