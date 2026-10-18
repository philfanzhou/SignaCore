# Gateway Auth Capabilities: Requirements

## Overview

`GET /api/gateway/auth-capabilities` returns the login methods the calling application currently
permits. The application's registration in SignaCore is the single source of truth; a site must
not add its own SMS enablement flag or use administrator credentials to read its own capabilities.

## Request

```http
GET /api/gateway/auth-capabilities HTTP/1.1
X-Admin-AppId: OrderService
X-Admin-AppSecret: <application secret>
```

The route takes no parameters. Query-string values such as `appId` or `app_id`, and any request
body, are ignored: the application is always the one the headers authenticated.

## Success response

`200 OK` with `Cache-Control: no-store` and exactly two boolean fields:

```json
{ "passwordEnabled": true, "smsLoginEnabled": false }
```

| Field | Value |
| --- | --- |
| `passwordEnabled` | Always `true`. The password grant has no per-application switch, so every application that passes gateway authentication may use it. |
| `smsLoginEnabled` | `true` when the application's SMS login mode is `ManualApproval` or `AutoProvision`; `false` when it is `Disabled`. |

`smsLoginEnabled` describes the permitted method only. It is `true` for an enabled mode even when
the application has no SMS provider profile (for example, when only bypass phones sign in), and it
does not mean a particular phone is approved, will be provisioned, or will receive a code.

## Failure response

Missing or wrong credentials, an unknown AppId, an inactive application, and an expired
registration all return the existing generic gateway answer, with `Cache-Control: no-store`:

```http
HTTP/1.1 401 Unauthorized
Cache-Control: no-store
Content-Type: application/json; charset=utf-8

{"message":"Invalid or missing gateway credentials."}
```

A user access token, a management session, or an identity cookie alone never authenticates the
route. There is no 403 answer.

Shared infrastructure answers keep their existing behavior and carry no capability data: the
global per-IP rate limiter's `429`, and an unhandled-exception `500`.

## Freshness and state

- The policy is read from the database on every request. A committed change to an application's
  SMS mode is visible on the next request, on every instance, without a restart.
- The read creates or updates no account, login, admission, OTP, identity session, refresh-token,
  login-history, or login-attempt row.
- A request the client abandons propagates cancellation and never produces a success answer.

## What is and is not guaranteed

- **Guaranteed:** the answer belongs to the authenticated calling application only; it reflects
  the committed policy at request time; the 200 and the 401 carry `no-store`.
- **Not guaranteed:** that SMS delivery or account admission will succeed when `smsLoginEnabled`
  is `true`; that a page already rendered from an earlier answer is invalidated when the policy
  changes; that in-flight requests are cancelled when the policy changes; that previously issued
  tokens are revoked.

## Caller responsibilities

- Keep the application secret on the server; call the route from the site's backend with the
  site's own configured application.
- Treat the answer as UI information, not authorization. `/api/auth/sms-code` and
  `/api/auth/token` enforce the policy themselves, so handle their failures even after a `true`
  answer.
- Use HTTPS, or TLS termination in front of SignaCore, for every gateway call.

## Compatibility

The route is additive. The only other change is an additive `Cache-Control: no-store` header on
the generic gateway 401, which every `GatewayApp`-protected route shares (`/api/auth/token`,
`/api/auth/sms-code`, `/api/auth/callback/register`, `/api/gateway/users/*`, `/metrics`); its status
and body are unchanged. There is no schema, migration, configuration, claim, or admin console
change. Rolling back the binary removes the route and the header and leaves stored policy intact.
