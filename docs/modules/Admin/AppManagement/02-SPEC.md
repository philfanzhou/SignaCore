# Application Management: Requirements

## Overview

Administrators create, list, inspect, and delete client application registrations.

## Functional requirements

1. Validate caller authentication and all required inputs before changing state.
2. Execute the operation through the domain and repository abstractions.
3. Return the standard JSON response and an appropriate HTTP status.
4. Preserve transaction boundaries and cancellation-token propagation.
5. Record security-relevant activity where the audit policy requires it.

## Per-application policies

Beyond registration and callbacks, an application carries four policies that administrators set:

| Policy | Endpoint |
| --- | --- |
| LDAP admission | `PUT /api/admin/apps/{appId}/ldap-policy` |
| SMS admission | `PUT /api/admin/apps/{appId}/sms-policy` |
| WeChat admission | `PUT /api/admin/apps/{appId}/wechat-policy` |
| Access-token audience | `PUT /api/admin/apps/{appId}/audience-mode` |

WeChat admissions are revoked with `DELETE /api/admin/apps/{appId}/wechat-users/{loginId}` and restored
with `POST .../restore`. A user re-binding cannot clear a revocation, so revoking is not merely advisory.

A WeChat mode other than `Disabled` is rejected when the deployment has no WeChat credentials: a policy
that cannot be honoured is refused at the point of configuration rather than at the user's first login
attempt. The SMS provider profile is optional, because it governs only code delivery: an application
may leave it unset and admit the phones on the `Sms:BypassPhones` allow-list with the fixed
`Sms:BypassCode`, which is how a test deployment runs without provider credentials. A profile key that
is not present in `Sms:Profiles` is still rejected, so a typo cannot silently disable delivery, and
`POST /api/auth/sms-code` reports the missing provider when a code is requested without one.

Changing the audience mode alters the `aud` claim of every subsequently issued access token for that
application; the coordinated rollout is described in
[conformance](../../../overview/StandardsConformance.md).

## Exchange trusts

An application may be configured to accept refresh tokens issued to another application, so a user
signed in to one reaches the other without re-authenticating:

| Operation | Endpoint |
| --- | --- |
| List the source applications this application trusts | `GET /api/admin/apps/{appId}/exchange-trusts` |
| Add a source application | `POST /api/admin/apps/{appId}/exchange-trusts` with `{ "sourceAppId": "..." }` |
| Remove a source application | `DELETE /api/admin/apps/{appId}/exchange-trusts/{sourceAppId}` |

The edge is directed: `{appId}` accepting tokens from `{sourceAppId}` does not imply the reverse.
Adding one is not a small change — every holder of a source-application refresh token can obtain a
session at this application for the same account, so a privilege difference between the two must be
enforced by this application's callback and authorization rules. Removing an edge stops further
exchanges but does not end sessions already minted from it, which are bound to this application and
its own admission records. Adding an existing edge is not an error, and an application cannot trust
itself. See [ADR 0003](../../../adr/0003-cross-application-refresh-grant.md) and the
[grant behaviour](../../Auth/GetToken/02-SPEC.md).

## Security requirements

Administrative endpoints require an authenticated JWT with the admin role.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

## Data

The feature owns or reads app_registrations, app_exchange_trusts, app_ldap_accesses, and app_sms_accesses. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.
