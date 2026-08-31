# UserInfo

**Status: target design.** Read the [directory boundary](./README.md) and the
[canonical model](./CanonicalSemanticModel.md) first.

`GET /oauth2/userinfo` is a server-to-server projection for a confidential BFF holding an
interactive access token. It is not the existing `/api/profile/*` API, a browser profile endpoint,
or a general validator for every self-issued access token.

## Request boundary

Canonical `IN-28` accepts exactly one `Authorization` header with an ASCII case-insensitive
`Bearer` scheme and a compact ASCII JWT of at most 8192 characters. The endpoint has no request
body. It rejects multiple authorization values and every query, form, cookie, ID-token,
refresh-token, or client-secret alternative.

Bearer tokens remain BFF-to-SignaCore secrets under `DF-07`. The authorization header is redacted
before application logging, tracing, metrics, exception capture, and audit construction. Responses
use `Cache-Control: no-store`, `Pragma: no-cache`, and a restrictive referrer policy. They are never
logged as complete JSON or copied to audit details.

## Validation pipeline

After structural input validation, one captured UTC time drives the following checks:

1. Require `typ: at+jwt`, an allowed RS256 signature and `kid`, the exact SignaCore issuer, and
   valid token times.
2. Resolve the token's application and require the exact audience/client binding for that
   application. The endpoint must not reuse the current `UserProfile` policy, whose deliberately
   broader audience rules serve the existing profile API.
3. Require the canonical interactive `scope` representation, `openid`, and `sid`, and bind subject,
   application, audience, and session without inference or fallback.
4. Load the current application, account, and identity session. Require the application and account
   to be active, the session to exist and be live, its account to equal `sub`, and its
   application-specific max-age to remain usable.
5. Intersect optional token scopes with the application's current allow list and build `PS-16`.

UserInfo is a live read, not session activity. It never slides idle expiry and never writes a
session or response artifact. Removing a scope can reduce optional claims but cannot change the
token's downstream lifetime (`EV-13`). `offline_access` has no effect on UserInfo (`EV-11`).

## Error contract

| Observation | HTTP result | `WWW-Authenticate` |
| --- | --- | --- |
| Authorization header missing | 401 | Bare `Bearer` |
| Malformed/multiple header or alternate carrier | 400 `invalid_request` | `Bearer error="invalid_request"` |
| Bad `typ`, signature, issuer, time, client/audience binding, or current application/account/session state | 401 `invalid_token` | `Bearer error="invalid_token"` |
| Signature-valid access token lacks the interactive claims or `openid` scope | 403 `insufficient_scope` | `Bearer error="insufficient_scope"` |

These are the `IN-28`/`IN-29` classes. Error descriptions are fixed English text when present and
never identify the failed cryptographic, binding, account, application, or session predicate. A
malformed request does not trigger live-state reads. No failure changes session, code, or token
state.

## Claims

`PS-16` is the complete response contract. Every successful response contains the stable account id
as `sub`, byte-for-byte identical to the ID-token subject. If both the token and current policy
contain `profile`, the response also contains the bound Password username as `name` and the current
non-null account nickname as `nickname`.

No callback is invoked. UserInfo returns no role, permission, credential-security, phone, email,
application, provider, or refresh-family claim. It neither echoes token claims blindly nor invents
empty optional fields. The BFF decides whether and how to expose any resulting profile through its
own browser session (`DF-15`).

## CORS and transport

The endpoint is intentionally unavailable to browser CORS. It sends no
`Access-Control-Allow-Origin` or credentials headers and does not handle a UserInfo preflight. The
runtime implementation must explicitly opt out of the host's current global `AdminWeb` CORS policy;
merely omitting endpoint-specific CORS is insufficient while that policy is applied globally.

TLS is required at the deployment boundary. No browser cookie authenticates UserInfo, so CSRF is
not its authorization mechanism. The BFF's own browser-facing profile/session behavior remains
outside SignaCore's contract.

## Test mapping and activation

Contract tests cover each error row above, mixed-case Bearer, multiple headers, every alternate
carrier, maximum length and non-ASCII input, exact per-application audience, absent/mismatched
`sid`, inactive account/application, missing/expired/revoked session, application max-age, current
scope removal, and claim omission. `SC-10`–`SC-12` prove time and policy propagation; `SC-18` proves
that missing authority invents no state.

The route is not usable and `userinfo_endpoint` stays absent until #55 is implemented after #96
(`AC-08`). This target document changes no current `/api/profile/*` route, JWT policy, CORS policy,
grant, or metadata (`AC-14`).
