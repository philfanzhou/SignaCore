# RP-Initiated Logout

**Status: target design.** See [README](./README.md).

`GET /oauth2/logout` ends the identity session and returns the browser to the application (OpenID
Connect RP-Initiated Logout 1.0). Front-channel and back-channel logout are not in this phase: both
require SignaCore to call out to every application a session touched, which is a fan-out design with
its own failure and timeout semantics.

## Request

| Parameter | Required | Bounds | Rule |
| --- | --- | --- | --- |
| `id_token_hint` | Yes | A JWT | An ID token issued by this issuer to the requesting client |
| `post_logout_redirect_uri` | No | 1–500 chars | Exact match against the client's registered set |
| `state` | No | 22–128 chars, `[A-Za-z0-9._~-]` | Echoed on the redirect when one happens |
| `client_id` | No — ignored | — | The client is identified by `id_token_hint` |

`id_token_hint` is **required**, which is stricter than the specification's RECOMMENDED. Without it,
`/oauth2/logout` is an unauthenticated endpoint that ends a session on a GET — a logout CSRF that any
page can trigger, and a nuisance rather than a compromise, but a free one. Requiring the hint also
identifies the client, which is what makes the redirect URI check possible.

The hint is validated for signature, issuer, and `aud`, but **not** for `exp`. A user logging out
after a long session legitimately holds an expired ID token, and refusing it would leave them unable
to sign out. `iat` older than 24 hours is rejected, which bounds how long a captured hint stays
usable. The hint proves which client and which session, not that the bearer is authorized — the
session cookie does that.

## Processing

1. Parse and validate `id_token_hint`: signature, `iss`, `aud` resolves to an active application,
   `iat` within 24 hours. Failure → local error page, HTTP 400, no redirect.
2. If `post_logout_redirect_uri` is present, match it exactly against that client's
   `post_logout_redirect_uris`. No match → local error page, HTTP 400, **no redirect**. Same rule as
   the authorization endpoint: an unverified URI is never a destination.
3. Read `sid` from the hint. If a session with that identifier exists and belongs to the account in
   `sub`, revoke it.
4. Delete `__Host-signacore_identity` with the same attributes it was set with.
5. Redirect to the verified `post_logout_redirect_uri` with `state` echoed if supplied; if none was
   supplied, render a local "you have signed out" page, HTTP 200.

There is no confirmation prompt. The request is authenticated by `id_token_hint` and by the session
cookie, and the specification's prompt exists for the unauthenticated case this design does not
allow.

Steps 3 and 4 are idempotent. Logging out twice, or logging out with a session that has already
expired, succeeds and redirects: reporting "you were not signed in" would be an oracle for session
state and would strand a user whose session expired mid-click.

Step 3 revokes only the session named by `sid`. Other sessions for the same account, in other
browsers, are untouched. "Sign out everywhere" is an account-security feature, not a protocol one,
and is not in this phase.

## What logout revokes

| Artifact | Effect |
| --- | --- |
| The identity session named by `sid` | Revoked immediately, on every instance |
| `__Host-signacore_identity` | Deleted from this browser |
| Unredeemed authorization codes from that session | Invalidated |
| Refresh tokens bound to that session | Revoked, for every application |
| Access tokens issued from that session | **Not** revoked; they expire within 15 minutes |
| `qz_admin_session` | Untouched |
| Sessions in other browsers | Untouched |

Revoking refresh tokens across every application is the deliberate part. A user who signs out expects
to have signed out, and leaving another application able to refresh silently against a dead session
would make the button a lie. Access tokens are the one thing that cannot be recalled; 15 minutes is
the bound, and it is why the interactive lifetime is short.

`qz_admin_session` is untouched because it is a different privilege. Signing out of an application
must not sign an operator out of SignaCore's own console, any more than the reverse.

## Errors

| Condition | Result |
| --- | --- |
| `id_token_hint` missing, malformed, wrong issuer, wrong signature, or `iat` older than 24 hours | Local page, 400 |
| `aud` resolves to no application, or an inactive one | Local page, 400 |
| `post_logout_redirect_uri` supplied but unregistered | Local page, 400 |
| No session cookie, or the session is already gone | Success — revoke what can be revoked, redirect as normal |
| `sid` names a session belonging to a different account than `sub` | Local page, 400; nothing is revoked |
| Internal failure | Local page, 500; the cookie is deleted anyway |

The local error page follows the same rules as the authorization endpoint's: no reflected
`post_logout_redirect_uri` as a link, no `Location` header, no reflected input without contextual
encoding.

Every response carries `Cache-Control: no-store`, `Pragma: no-cache`, and
`Referrer-Policy: no-referrer`.

## Rate limiting

| Partition | Limit |
| --- | --- |
| `logout:{client_ip}` | 60 / minute |

Rejection is a local 429, never a redirect.
