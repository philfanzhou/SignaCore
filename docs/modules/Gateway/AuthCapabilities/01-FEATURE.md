# Gateway Auth Capabilities

## Purpose

A site that signs users in through the legacy Password and SMS grants asks SignaCore which login
methods its own application currently permits, so it can show or hide SMS login from SignaCore's
application policy instead of keeping a second SMS switch of its own.

## Primary interface

`GET /api/gateway/auth-capabilities`, authenticated with the calling application's
`X-Admin-AppId` and `X-Admin-AppSecret` headers.

```json
{ "passwordEnabled": true, "smsLoginEnabled": false }
```

## Acceptance summary

- The answer always describes the authenticated calling application; no request parameter can
  select another application.
- `smsLoginEnabled` follows the application's stored SMS login mode on every request, with no
  restart and no cache to clear.
- Failed authentication returns the existing generic gateway 401 and reveals nothing about why.
- Both the 200 and the 401 carry `Cache-Control: no-store`.
- The read changes no account, admission, OTP, session, token, or login-history state.

## Out of scope

The route does not report whether a particular account can sign in, whether an SMS provider is
configured or reachable, or whether a password exists. It does not change application policy, the
token and SMS code endpoints, hosted login, or any credential or session behavior.

## Related documents

- [Requirements](./02-SPEC.md)
- [Design](./03-DESIGN.md)
- [Tasks](./04-TASKS.md)
- [Tests](./05-TESTS.md)
- [Conventions](./06-CONVENTIONS.md)
