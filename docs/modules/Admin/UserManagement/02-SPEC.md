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

The six user-management actions use the `AdminSession` authorization policy. It rides the fixed
shared management scheme `ServiceMantle.ManagementCookie`
(`ManagementSessionDefaults.AuthenticationScheme`), requires an authenticated user, and requires
the principal to resolve to exactly one legitimate management operator holding the `Admin`
permission (`ManagementPermissionRequirement`). Operator login is the shared ServiceMantle
management-session entry `POST /management/v1/session/login`, which sets the fixed cookie
`__Host-ServiceMantle.Management`; session issuance, lifetime, logout, and CSRF rules are owned by
the [ServiceMantle management-session contract](https://github.com/philfanzhou/ServiceMantle/blob/main/docs/contracts/management-session.md)
and are not restated here. The shared `AddManagementCookieAuthentication` capability also sets
every default authentication scheme to the management scheme. A JWT or an `admin` role alone does
not satisfy this policy, and a principal carrying only the legacy name claims resolves to no
operator and is rejected. Credentials and secrets must never be returned.

This describes current administration behavior. The separate browser identity scheme is a future
OIDC capability; its authoritative boundary is documented in
[Identity Login: Isolation from administration](../../../oidc/IdentityLogin.md#isolation-from-administration).
That target design does not change the current admin session requirements.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

### Current implementation and test evidence

- [ServiceCollectionExtensions](../../../../src/SignaCore.Host/ServiceCollectionExtensions.cs)
  registers the `AdminSession` policy on the fixed management scheme with the authenticated-user
  and Admin-permission requirements. The default schemes and the cookie itself come from the
  shared package, composed in
  [ManagementSessionComposition](../../../../src/SignaCore.Host/Management/ManagementSessionComposition.cs)
  via `AddManagementCookieAuthentication`; the same file owns the login adapter that invokes
  [SignaCoreManagementIdentityProvider](../../../../src/SignaCore.Host/Management/SignaCoreManagementIdentityProvider.cs).
- [AdminController](../../../../src/SignaCore.Host/Controllers/AdminController.cs) applies the
  policy to `GetUsers`, `CreateUser`, `CreatePhoneUser`, `UpdateUserRemark`, `UpdateUserNickname`,
  and `UpdateUserStatus`, and projects the resolved management operator in `GetCurrentSession`.
  It no longer has login or logout actions.
- [AdminSessionPolicyTests](../../../../tests/SignaCore.Tests/Host/Management/AdminSessionPolicyTests.cs)
  are direct policy tests against the composed host services:
  `AManagementOperatorWithAdminPermission_IsAuthorized`,
  `AnAuthenticatedPrincipalWithOnlyLegacyNameClaims_IsRejected`, and
  `BothPolicies_RideTheFixedManagementScheme`. They evaluate the authorization policy itself, not
  the HTTP pipeline.
- [ManagementSessionContractTests](../../../../tests/SignaCore.IntegrationTests/Integration/ManagementSessionContractTests.cs)
  are the HTTP-layer evidence for the session contract, including
  `Login_WithBootstrapAdmin_Returns204AndSetsTheFixedManagementCookie` and
  `Login_WithNonBootstrapAccount_Returns401AndRecordsTheBootstrapReason`.
- [AdminControllerTests](../../../../tests/SignaCore.Tests/Host/Controllers/AdminControllerTests.cs)
  covers the user-management actions and the session projection as direct controller tests. These
  do not execute authentication middleware.
- [IdentityHttpEndpointsTests](../../../../tests/SignaCore.IntegrationTests/Integration/IdentityHttpEndpointsTests.cs)
  uses `CreateAdminHttpClientAsync` to sign in through the shared management-session entry
  `POST /management/v1/session/login` (with the `X-ServiceMantle-Request` header, addressed over
  `https://localhost` because the management cookie is always `Secure`) and to retain the cookie.
  `SettingsApi_RequiresAnAdminSessionAndNeverReturnsSecretValues` verifies anonymous 401 and
  authenticated 200 on a management endpoint using the same policy; it is supporting session
  evidence, not an HTTP authorization matrix for the six user-management actions.

## Data

The feature owns or reads accounts, user_logins, password_credentials, and ldap_credentials. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.
