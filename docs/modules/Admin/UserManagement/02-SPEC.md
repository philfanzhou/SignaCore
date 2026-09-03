# User Management: Requirements

## Overview

Administrators create, inspect, update, and deactivate local, phone, and LDAP-backed user accounts.

## Functional requirements

1. Validate caller authentication and all required inputs before changing state.
2. Execute the operation through the domain and repository abstractions.
3. Return the standard JSON response and an appropriate HTTP status.
4. Preserve transaction boundaries and cancellation-token propagation.
5. Record security-relevant activity where the audit policy requires it.

## Security requirements

The six user-management actions use the `AdminSession` authorization policy. It requires an
authenticated principal with `admin_access=true` and uses the default `Cookies` authentication
scheme (`qz_admin_session`). A successful bootstrap-administrator login at
`POST /api/admin/session/login` creates that principal with `ClaimTypes.NameIdentifier`,
`ClaimTypes.Name`, and `admin_access=true`. A JWT or an `admin` role alone does not satisfy this
policy. Credentials and secrets must never be returned.

This describes current administration behavior. The separate browser identity scheme is a future
OIDC capability; its authoritative boundary is documented in
[Identity Login: Isolation from administration](../../../oidc/IdentityLogin.md#isolation-from-administration).
That target design does not change the current admin session requirements.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

### Current implementation and test evidence

- [ServiceCollectionExtensions](../../../../src/SignaCore.Host/ServiceCollectionExtensions.cs)
  registers the default cookie scheme and the `AdminSession` policy.
- [AdminController](../../../../src/SignaCore.Host/Controllers/AdminController.cs) creates the login
  principal and applies the policy to `GetUsers`, `CreateUser`, `CreatePhoneUser`,
  `UpdateUserRemark`, `UpdateUserNickname`, and `UpdateUserStatus`.
- [AdminControllerTests](../../../../tests/SignaCore.Tests/Host/Controllers/AdminControllerTests.cs)
  covers bootstrap-administrator login, rejection of other accounts, and user-management actions.
  These direct controller tests do not execute authentication middleware.
- [IdentityHttpEndpointsTests](../../../../tests/SignaCore.IntegrationTests/Integration/IdentityHttpEndpointsTests.cs)
  uses `CreateAdminHttpClientAsync` to sign in through the real HTTP login endpoint and retain the
  cookie. `SettingsApi_RequiresAnAdminSessionAndNeverReturnsSecretValues` verifies anonymous 401
  and authenticated 200 on a management endpoint using the same policy; it is supporting session
  evidence, not an HTTP authorization matrix for the six user-management actions.

## Data

The feature owns or reads accounts, user_logins, password_credentials, and ldap_credentials. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.
