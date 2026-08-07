# Token Issuance: Requirements

## Overview

Clients exchange password, SMS, WeChat, LDAP, or refresh-token credentials for an RS256 JWT and a rotating refresh token.

## Functional requirements

1. Validate caller authentication and all required inputs before changing state.
2. Execute the operation through the domain and repository abstractions.
3. Return the standard JSON response and an appropriate HTTP status.
4. Preserve transaction boundaries and cancellation-token propagation.
5. Record security-relevant activity where the audit policy requires it.

## Endpoints

The same issuance pipeline is reachable through two endpoints, which differ only in wire format:

- `POST /api/auth/token` — the frozen JSON contract described by this document.
- `POST /oauth2/token` — RFC 6749 form-encoded, with standard error codes and grant names.

See [conformance](../../../overview/StandardsConformance.md) for the standards surface and the
per-application `aud` migration.

## Application-scoped admission

SMS, LDAP, and WeChat grants are admitted per application, never globally:

| Grant | Application policy column | Modes |
| --- | --- | --- |
| `sms` | `sms_login_mode` | `Disabled`, `ManualApproval`, `AutoProvision` |
| `ldap` | `ldap_login_mode` | `Disabled`, `ManualApproval`, `AutoProvision` |
| `wechat_code` | `wechat_login_mode` | `Disabled`, `BindRequired`, `AutoProvision` |

WeChat has no administrator pre-approval mode because an OpenId is only knowable after the user
authorizes. Under `BindRequired` the binding is created by the user through `POST /api/profile/wechat`;
under `AutoProvision` the first successful login provisions the account. Administrators revoke through
`DELETE /api/admin/apps/{appId}/wechat-users/{loginId}`, which also revokes the refresh tokens issued
from that identity.

A refresh-token grant re-evaluates the current admission of the identity that started the session, so
revoking access ends the session at the next refresh instead of at access-token expiry.

## Security requirements

Every request is bound to a registered application. Secrets are verified with library primitives, refresh tokens rotate, and failures do not expose account existence.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

## Data

The feature owns or reads accounts, app_registrations, password_credentials, otps, user_logins, app_sms_accesses, app_wechat_accesses, ldap_credentials, app_ldap_accesses, login_attempts, and refresh_tokens. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.
