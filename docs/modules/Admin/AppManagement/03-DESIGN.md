# Application Management: Design

## Components

AdminController, AppRegistrationRepository, and AppRegistrationEntity.

## Request flow

1. ASP.NET Core middleware assigns or propagates a correlation identifier.
2. The controller or hosted service validates its security context and input.
3. Domain services apply policy and coordinate repositories.
4. EF Core persists changes using the configured provider.
5. The caller receives a normalized response; failures pass through centralized exception handling.

## Interface

Primary interface: POST/GET/DELETE /api/admin/apps.

## Persistence

Relevant tables: app_registrations, app_exchange_trusts, app_ldap_access, and app_sms_access. PostgreSQL migrations live in Database, while SQLite uses its provider-specific migration assembly.

## Design constraints

- Domain code does not depend on the web host.
- Controllers contain transport concerns, not persistence rules.
- Secrets are never included in diagnostic payloads.
- Async calls propagate CancellationToken.
- Provider-specific behavior must be covered by database contract tests.
