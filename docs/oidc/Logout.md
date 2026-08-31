# Prepared Logout

**Status: target design.** Read the [directory boundary](./README.md) and the
[canonical model](./CanonicalSemanticModel.md) first.

SignaCore uses an authenticated preparation request followed by an opaque browser handle. This
preserves the first-party BFF's server-only ID-token boundary while still correlating logout with
the exact identity session. It is deliberately not the standard RP-Initiated Logout wire shape, so
Discovery does not publish `end_session_endpoint` (`AC-10`).

## Step 1: authenticated preparation

The BFF sends `POST /oauth2/logout/requests` over authenticated TLS. The request is a bounded UTF-8
form of at most 16 KiB. Unknown fields are rejected. Confidential-client authentication is exactly
the exclusive Basic-or-form contract in `IN-20`/`IN-30`; browser cookies are not client
authentication.

| Field | Contract |
| --- | --- |
| `id_token_hint` | Required 1–8192-character compact ASCII JWS; `IN-31` validates RS256 signature, issuer, authenticated-client audience, `sub`, `sid`, and an `iat` no older than 24 hours. Only this preparation check ignores `exp` |
| `post_logout_redirect_uri` | Optional 1–500 ASCII characters; exact ordinal match to the authenticated client's registered post-logout set, with no normalization (`IN-32`) |
| `state` | Optional 22–128 ASCII characters from `[A-Za-z0-9._~-]`; opaque and later echoed byte-for-byte (`IN-33`) |

The application must be active before its post-logout registration can be trusted (`EV-09`). Any
authentication, token, URI, state, or form failure is a local JSON error and creates no logout row.
No error redirects to request input.

Success generates 32 random bytes, exposes their 43-character base64url form once, and stores only
the versioned SHA-256 digest with the verified identifiers, URI, state, and five-minute lifecycle
from `PS-08`. The ID token is validated in request memory and is never stored. The no-store JSON
response contains one relative or same-origin `logout_uri`; its only query value is the new
`logout_handle` (`IN-34`).

## Step 2: browser completion

The BFF navigates the browser to `GET /oauth2/logout?logout_handle=...`. The handle is the sole
supported query field, exactly 43 base64url characters, digest-looked-up, five-minute, and
single-use (`IN-35`). The GET accepts no body, ID token, redirect URI, state, client credential, or
alternate handle carrier.

Missing, malformed, absent, expired, or consumed handles produce a local 400 with no redirect and
no invented consumption, revocation, or audit (`SC-18`). All local and redirect responses use
no-store/no-cache/no-referrer protections; the query value is redacted from logs and telemetry.

The protected identity cookie is authoritative only after exact comparison with the stored logout
request `sid` and confirmation that the session's account equals the stored `sub` (`IN-36`). A
missing, unusable, or mismatching cookie follows `EV-07`. An impossible same-session-id but
different-account record is treated as corruption: local 400, no state write, and no redirect.

## Atomic completion and external result

Completion digest-loads the request to identify its session, then enters the provider execution
strategy. When a matching session may exist, it locks the session before the logout-request and
family rows; otherwise it locks the request without inventing a session. It repeats handle,
lifecycle, and binding checks under lock, then conditionally consumes the request exactly once.

A matching usable cookie executes `EV-06`: the transaction consumes the request, revokes the
session with reason `logout`, and explicitly revokes every bound family. Bound codes remain
unconsumed and fail their live-session check. A missing, unusable, or mismatching cookie executes
`EV-07`: it consumes the request but changes no session, code, or family state. Both paths have the
same externally successful shape, preventing a session-state oracle.

After a successful commit, SignaCore deletes any presented identity cookie using the exact
`PS-18` attributes. It does not touch `qz_admin_session`. If a verified post-logout URI exists, the
response redirects to that exact stored URI and appends the stored state byte-for-byte using safe
URI construction. Otherwise it returns the same local success page/status for both paths. No
redirect is released before commit.

The operation is idempotent at the durable session-state level, not by replaying a consumed handle.
A second use of one handle is local 400. A new valid prepared request for an already revoked matching
session can consume safely without changing the established revocation fact and returns the normal
success shape. Cancellation before commit rolls back consumption and revocation; after commit it
cannot undo either (`EV-18`, `SC-20`). Cookie deletion follows the committed result.

## Concurrency with code redemption

Logout and code redemption lock the same session first. `EV-28` permits exactly two serial results:

- Logout-first consumes the handle and revokes the session; redemption then returns generic
  `invalid_grant`, leaves the code unconsumed, and emits no replay audit (`SC-05`).
- Redemption-first commits one token set and optional family; logout then revokes the session and
  every bound family. Issued access and ID tokens remain valid downstream only to `exp`, while
  UserInfo fails the live check (`SC-06`).

Neither provider may manufacture a replay audit from the logout-first case. PostgreSQL proves both
orders across shared-database instances; SQLite proves them as concurrent requests to its supported
single instance (`PS-22`).

## Sensitive values and compatibility

`DF-08` keeps the ID token BFF-to-SignaCore only, including logout. `DF-10` permits only the opaque
handle in the browser URL. `DF-12` permits navigation only to a previously registered and exactly
verified post-logout URI. Client secret, ID token, raw handle, cookie, untrusted URI, and state never
enter logs, audit details, traces, metrics, or exceptions. Audit records use only bounded public ids
and result categories.

Tests directly execute `SC-05`, `SC-06`, `SC-15`, `SC-18`, and `SC-20`, plus double completion,
expired-boundary, cookie mismatch, corrupt binding, redirect encoding, and response-header cases.
The current admin logout route and cookies remain unchanged. Runtime activation belongs to #68 and
publishes no standard logout metadata (`AC-10`); this document itself changes no route or Discovery
response (`AC-14`).
