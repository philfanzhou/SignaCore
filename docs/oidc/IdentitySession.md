# Identity Session

**Status: target design.** See [README](./README.md).

The identity session is SignaCore's own browser session: "this browser has proved who it is." It is
not `qz_admin_session`, which means "this browser may administer SignaCore." Keeping them apart is
the point of this document.

## Two cookies, no overlap

| | `qz_admin_session` (exists today) | `__Host-signacore_identity` (new) |
| --- | --- | --- |
| Means | May administer SignaCore | Proved an identity |
| Scheme | `CookieAuthenticationDefaults.AuthenticationScheme` | A new, separately named scheme |
| Accepted at | `/api/admin/*`, the admin console | `/oauth2/authorize` and the identity login pages |
| Rejected at | `/oauth2/authorize`, identity login pages | `/api/admin/*`, the admin console |
| Contents | Unchanged | An opaque session identifier and nothing else |
| Data Protection purpose | Unchanged | A distinct purpose string |
| Established by | Admin login | Identity login, Password credential only |

Both may exist in one browser at once and neither confers the other. Establishing an identity
session MUST NOT create, refresh, extend, or invalidate an admin session, and the reverse holds too.
Signing out of one leaves the other alone.

Separate Data Protection purposes mean a ciphertext minted for one scheme cannot be validated by the
other even though both use the same key ring. That is a defence against a routing mistake, not
against an attacker — an attacker who can forge one purpose can forge both — but routing mistakes
are the realistic failure here.

## Cookie attributes

| Attribute | Value | Rationale |
| --- | --- | --- |
| Name | `__Host-signacore_identity` | The `__Host-` prefix forces `Secure`, `Path=/`, and no `Domain`, enforced by the browser rather than by our configuration |
| `HttpOnly` | Yes | Script must not read it |
| `Secure` | Yes | Implied by `__Host-`, set explicitly anyway |
| `SameSite` | `Lax` | See below |
| `Path` | `/` | Required by `__Host-` |
| `Domain` | Not set | Required by `__Host-`; no subdomain shares it |
| Value | Opaque session id, 32 CSPRNG bytes base64url, inside the Data Protection envelope | The cookie carries no claims |
| Idle expiry | 30 minutes, sliding | A console left open over lunch asks again |
| Absolute expiry | 12 hours, not extendable | Bounds a stolen cookie regardless of activity |

`SameSite=Lax` rather than `Strict` is a deliberate, load-bearing choice. `/oauth2/authorize` is
reached by a cross-site top-level GET navigation — the BFF redirects the browser there — and `Strict`
withholds the cookie on exactly that navigation. Every session would appear absent, every login would
be re-prompted, and the sliding window would never advance. `Lax` sends cookies on top-level GET and
withholds them on cross-site POST and subresource requests, which is the property that matters:
`/oauth2/authorize` is idempotent, has no side effect beyond issuing a code that is useless without
the client secret and the `code_verifier`, and the login POST that does have side effects is
`SameSite=Lax`-protected *and* separately CSRF-protected.

The absolute lifetime is not extendable by any request. When it passes, the session ends even mid-
interaction, and the next `/oauth2/authorize` sends the browser to login.

## Server-side session record

The cookie carries an identifier; authority lives in the database. This is what makes revocation
work across instances — a stateless cookie can only be revoked by waiting for it to expire.

Every request that presents the cookie:

1. Unprotects the cookie. Failure → treat as no session, and delete the cookie.
2. Loads the session row by identifier. Missing → treat as no session, and delete the cookie.
3. Rejects the session if it is revoked, past its absolute expiry, or past its idle expiry.
4. Rejects the session if the account is disabled or deleted.
5. Advances the idle expiry, but never past the absolute expiry.

Step 4 is checked on every request, not cached from login. An account disabled at 10:00 cannot start
an authorization request at 10:01. Step 5 writes on every request; on PostgreSQL that write is
allowed to lag by up to one minute (write only when the stored value is more than a minute stale) so
a busy console does not turn every page view into a row update.

Fields are specified in [Persistence](./Persistence.md#identity_sessions).

## Login continuation

When `/oauth2/authorize` reaches step 10 with no usable session, the browser must log in and then
resume the *original* request. The original request is not carried through the login page as a URL.

1. SignaCore stores the validated authorization request server-side and generates a **continuation
   handle**: 32 CSPRNG bytes, base64url, stored as a SHA-256 digest, 10-minute TTL, single-use.
2. The browser is redirected to the login page with that handle as its only parameter.
3. The login page renders no part of the authorization request. Not the redirect URI, not the scope,
   not the state.
4. On a successful credential check, SignaCore establishes the identity session, consumes the
   handle, reloads the stored request, and re-runs steps 1–9 and 11 of the
   [validation order](./AuthorizationEndpoint.md#validation-order). Step 10 is skipped because this
   operation has just established and validated the session that step 10 would inspect.

Storing the request server-side is what keeps the login page from becoming a redirect surface: with
a `returnUrl`-style parameter, anything that can reach the login page can choose where the browser
lands afterwards, and every such parameter has to be re-validated against the registered set at a
point where the code that does that validation is no longer obviously in the path.

A handle that is expired, unknown, or already consumed produces a local error page telling the user
to start again from their application. It MUST NOT redirect, because a consumed handle no longer has
a verified redirect URI attached to it.

This re-validation is not optional. Between the authorization request and the login, the application
may have been deactivated, its redirect URI removed, or its scopes narrowed. The stored request is
re-checked against current configuration from step 1: failures at steps 1 and 2 still produce a local
error page with no redirect; only failures at steps 3–9 or 11 may return to the newly re-verified
redirect URI. The fact that the URI was valid before login does not make a removed URI safe now.

## Login CSRF

The login form is protected by an antiforgery token bound to a `__Host-`-prefixed cookie,
independent of the identity session and of the continuation handle. A POST without a valid token
fails with HTTP 400 and a local page.

This is not redundant with `SameSite=Lax`. `Lax` does not protect against a same-site attacker — a
compromised or user-controlled page on the same registrable domain — and login CSRF has a specific
consequence here: an attacker who can make a victim's browser log in as the *attacker's* account
gets the victim to continue an authorization request under an identity the attacker controls. The
antiforgery token, being unguessable and per-session, is what removes that.

The login page also sets `Cache-Control: no-store`, `Pragma: no-cache`, and
`Referrer-Policy: no-referrer`.

## Credentials

Only the Password credential establishes an identity session in this phase.

- SMS, LDAP, and WeChat keep working at the token endpoint and gain no browser surface. Each carries
  its own admission policy, its own account-linking rules, and — for SMS — its own rate-limit and
  cost model; putting them behind a redirect flow is a separate design with separate audit
  questions, not a switch to flip.
- The existing lockout applies unchanged: `MaxFailedLoginAttempts = 5`, `LoginLockoutMinutes = 15`.
  A locked account gets the same generic failure message as a wrong password.
- The failure message MUST NOT distinguish "no such account", "wrong password", "disabled", and
  "locked out". The login page is unauthenticated and reachable by anyone with a continuation handle.

Successful and failed identity logins are recorded in the existing login-history and login-attempt
tables, tagged so an interactive login is distinguishable from a token-endpoint one.

## Ending a session

| Trigger | Effect |
| --- | --- |
| RP-initiated logout | Session revoked, cookie deleted; see [Logout](./Logout.md) |
| Idle expiry | Session unusable; the row is cleaned up by the existing cleanup job |
| Absolute expiry | Same |
| Account disabled | Every session for that account is unusable from the next request |
| Administrative revocation | Same, and audited |

Ending an identity session does not revoke access tokens already issued — they are self-contained
and expire on their own — and does not revoke refresh tokens unless the trigger says so. The full
matrix is in [StatePropagation](./StatePropagation.md).
