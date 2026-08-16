# Token Issuance: Design

## Components

TokenController, ValidatorFactory, validators, ClaimsResolver, TokenService, and RefreshTokenService.

## Request flow

1. ASP.NET Core middleware assigns or propagates a correlation identifier.
2. The controller or hosted service validates its security context and input.
3. Domain services apply policy and coordinate repositories.
4. EF Core persists changes using the configured provider.
5. The caller receives a normalized response; failures pass through centralized exception handling.

## Interface

Primary interface: POST /api/auth/token.

## Persistence

Relevant tables: accounts, app_registrations, app_exchange_trusts, password_credentials, otps, user_logins, login_attempts, and refresh_tokens. PostgreSQL migrations live in Database, while MySQL/MariaDB and SQLite use their provider-specific migration assemblies.

## Design constraints

- Domain code does not depend on the web host.
- Controllers contain transport concerns, not persistence rules.
- Secrets are never included in diagnostic payloads.
- Async calls propagate CancellationToken.
- Provider-specific behavior must be covered by database contract tests.
