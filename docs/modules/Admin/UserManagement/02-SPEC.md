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

The user-management actions use `AdminSession`, which requires an authenticated principal
resolving to one legitimate management operator with the `Admin` permission. The management
selector chooses the management Bearer scheme when an `Authorization` header is present on these
routes; it never falls back to a Cookie after Bearer rejection. Without that header, it chooses
`ServiceMantle.ManagementCookie`. An ordinary user JWT, application credentials, an `admin` role
alone, or legacy name claims do not grant management access. A resolved management operator without
`Admin` permission receives 403. The management session entries remain Cookie-only.

Cookie login is `POST /management/v1/session/login`, addressed over HTTPS with the
`X-ServiceMantle-Request: 1` guard. The fixed Cookie is `__Host-ServiceMantle.Management`.
The console uses its existing explicit management Bearer credential for management API calls.
The [shared management session contract](https://github.com/philfanzhou/ServiceMantle/blob/main/docs/contracts/management-session.md)
owns session issuance, lifetime, logout, and Cookie request guards. Current selector composition is
in [ManagementSessionComposition](../../../../src/SignaCore.Host/Management/ManagementSessionComposition.cs)
and policy requirements are registered by
[ServiceCollectionExtensions](../../../../src/SignaCore.Host/ServiceCollectionExtensions.cs).

### Administrator password reset

`POST /api/admin/users/{userId:guid}/reset-password` accepts `{ "newPassword": "..." }`.
It needs no old password and uses the existing password policy (at least eight characters,
including uppercase and lowercase letters and a digit) and hasher. Passwords are used exactly as
submitted; they are never trimmed, normalized, logged, or returned.

| Condition | Result |
| --- | --- |
| Existing account, exactly one local credential, valid password and administrator | 200, `OperationResponse`, `Password reset.` |
| Missing valid management identity / operator without Admin permission | Existing management 401 / 403 contract |
| Missing account | 404, `ErrorResponse` |
| Missing, null, empty, or weak new password | 400, `ErrorResponse` |
| No local password credential | 400, `ErrorResponse`; no credential is created |
| More than one local password credential | 409, `ErrorResponse`; no credential is selected |

The account and up to two local credentials are read inside a retryable explicit transaction.
Only the unique credential's `PasswordHash` is updated, and the affected row count must be one.
The `admin_password_reset` success audit targets `Account` and uses the resolved management
operator. The hash write and audit commit or roll back together, including audit/save failure and
cancellation before commit. Cancellation or transport failure after commit cannot undo the reset.

The username, account status, nickname, remark, failed-login counters, lockout deadline, existing
identity/management sessions and every token keep their existing state and lifetime. A disabled
account stays disabled and a locked account stays locked. New password checks that read the new
committed credential accept the new password and reject the old one; login requests that already
verified the old password retain the existing login behavior. For two successful resets, the last
database write wins and each commit has its own audit. No new concurrency/version protocol is added.

The account drawer offers **Reset password** only for `hasPassword` accounts. Its dialog displays
the target username and password/confirmation fields. Confirmation remains in the browser and
missing or mismatched inputs prevent submission. The request captures its target and rejects
repeat submission; old completions cannot mutate a later dialog. Success, cancel, dialog close,
drawer close, and account switch clear both fields. Failures show the standard error. Passwords
never enter browser storage, URLs, logs, or notifications. Administrators must communicate the
chosen password to the account owner themselves. No temporary password, forced change, recovery,
notification, bulk reset, unlock, or session revocation is provided.

This differs from self-service `POST /api/profile/password`, which requires the old password and
revokes account sessions and refresh tokens. Administrator reset deliberately keeps them active.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

### Current implementation and test evidence

- [ServiceCollectionExtensions](../../../../src/SignaCore.Host/ServiceCollectionExtensions.cs)
  registers the `AdminSession` policy on the management selector with the authenticated-user
  and Admin-permission requirements. The Cookie comes from the
  shared package and the Bearer selector is composed in
  [ManagementSessionComposition](../../../../src/SignaCore.Host/Management/ManagementSessionComposition.cs)
  via `AddManagementCookieAuthentication` and the management Bearer selector registration; the
  same file owns the Cookie login adapter that invokes
  [SignaCoreManagementIdentityProvider](../../../../src/SignaCore.Host/Management/SignaCoreManagementIdentityProvider.cs).
- [AdminController](../../../../src/SignaCore.Host/Controllers/AdminController.cs) applies the
  policy to `GetUsers`, `CreateUser`, `CreatePhoneUser`, `UpdateUserRemark`, `UpdateUserNickname`,
  `UpdateUserStatus`, and `ResetUserPassword`, and projects the resolved management operator in `GetCurrentSession`.
  Cookie login/logout remains in the shared management session entries.
- [AdminSessionPolicyTests](../../../../tests/SignaCore.Tests/Host/Management/AdminSessionPolicyTests.cs)
  are direct policy tests against the composed host services:
  `AManagementOperatorWithAdminPermission_IsAuthorized`,
  `AnAuthenticatedPrincipalWithOnlyLegacyNameClaims_IsRejected`, and
  `BothPolicies_RideTheManagementSelector`. They evaluate the authorization policy itself, not
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
  evidence, not an HTTP authorization matrix for every user-management action.
- [AdminPasswordResetEndpointTests](../../../../tests/SignaCore.IntegrationTests/Integration/AdminPasswordResetEndpointTests.cs)
  verifies the reset-specific HTTP authorization matrix, invalid inputs, target credential counts,
  subsequent password login, and sensitive-value canaries.

## Data

The feature owns or reads accounts, user_logins, password_credentials, and ldap_credentials. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.

The reset route and UI are additive. There are no dependencies, schema/migration, configuration,
JWT/JWKS, key, or deployment changes. Rolling back the code removes the entry and endpoint; already
reset hashes remain readable by the old version. Rollback does not restore original passwords.
