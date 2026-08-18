# Gateway User Query: Design

## Components

GatewayController, GatewayValidationService, UserQueryService, and repository abstractions.

## Request flow

1. ASP.NET Core middleware assigns or propagates a correlation identifier.
2. The controller or hosted service validates its security context and input.
3. Domain services apply policy and coordinate repositories.
4. EF Core persists changes using the configured provider.
5. The caller receives a normalized response; failures pass through centralized exception handling.

## Interface

Primary interface: /api/gateway/users.

## Persistence

Relevant tables: accounts, user_logins, and password_credentials. PostgreSQL migrations live in Database, while SQLite uses its provider-specific migration assembly.

## Design constraints

- Domain code does not depend on the web host.
- Controllers contain transport concerns, not persistence rules.
- Secrets are never included in diagnostic payloads.
- Async calls propagate CancellationToken.
- Provider-specific behavior must be covered by database contract tests.
