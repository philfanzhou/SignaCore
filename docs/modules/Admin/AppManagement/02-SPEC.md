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

A WeChat mode other than `Disabled` is rejected when the deployment has no WeChat credentials, and an
SMS mode other than `Disabled` is rejected without a configured provider profile: a policy that cannot
be honoured is refused at the point of configuration rather than at the user's first login attempt.

Changing the audience mode alters the `aud` claim of every subsequently issued access token for that
application; the coordinated rollout is described in
[conformance](../../../overview/StandardsConformance.md).

## Security requirements

Administrative endpoints require an authenticated JWT with the admin role.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

## Data

The feature owns or reads app_registrations, app_ldap_access, and app_sms_access. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.
