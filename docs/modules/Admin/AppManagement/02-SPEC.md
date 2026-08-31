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

## Interactive OIDC client configuration

An application also carries the interactive OIDC policy and two sets of browser URI registrations.
Both are disabled and empty for every application that does not explicitly configure them.

| Operation | Endpoint |
| --- | --- |
| Read the interactive configuration | `GET /api/admin/apps/{appId}/oidc` |
| Replace the interactive policy | `PUT /api/admin/apps/{appId}/oidc-policy` |
| Register browser URIs of one kind | `POST /api/admin/apps/{appId}/oidc/redirect-uris` with `{ "kind": "Redirect" \| "PostLogout", "uris": [...] }` |
| Remove one registration | `DELETE /api/admin/apps/{appId}/oidc/redirect-uris/{registrationId}` |

`GET /api/admin/apps` reports the same policy fields and both URI sets for every application. The
members it already returned keep their names, order, and meaning.

The policy is `clientType` (`Confidential` or the reserved `Public`), `allowAuthorizationCode`,
`allowedScopes` (a subset of `openid`, `profile`, `offline_access` that must contain `openid`),
`allowRefreshToken`, and an optional `identitySessionMaxAgeSeconds` between 1 and 43200. The audience
mode is not part of this request: it has its own endpoint, and enabling the code flow on an
application whose audience is still `Shared` is refused rather than silently changing that
application's `aud`.

Every request is one unit. A submitted set with one unacceptable value registers nothing, and a
policy request that would leave an unacceptable combination — code flow with no redirect URI, code
flow on a `Public` client, `offline_access` without refresh tokens — changes no field at all. The
same rule refuses removing the last redirect URI while the code flow is enabled.

Registration canonicalises a URI: the scheme and host are lowercased, a scheme-default port is
dropped, and an empty path becomes `/`. Path case, percent-encoding, query, and a trailing slash are
preserved, because they distinguish real destinations. At most ten URIs of each kind are accepted,
HTTPS is required outside development, and `localhost` is always rejected — development alone also
accepts the literal `127.0.0.1` or `[::1]` over HTTP.

A claims `callbackUrl` is a server-to-server registration and a redirect URI is a browser
destination. They have separate fields, separate validation, and separate endpoints; no value is
copied, defaulted, or written back between them.

Configuring an application does not make any OIDC endpoint usable and changes neither discovery
document. The staged activation is described in the
[interactive OIDC design](../../../oidc/README.md).

## Security requirements

Administrative endpoints require an authenticated JWT with the admin role.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

## Data

The feature owns or reads app_registrations, app_redirect_uris, app_exchange_trusts, app_ldap_accesses, and app_sms_accesses. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.
