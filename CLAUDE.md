# Repository Guidance

SignaCore is a .NET 10 identity and authentication service with a Vue 3 administrative console. Repository documentation, code comments, automation comments, and contributor-facing text should be written in English.

## Commands

```bash
dotnet build SignaCore.slnx
dotnet test tests/SignaCore.Tests/SignaCore.Tests.csproj
dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj
npm --prefix src/SignaCore.Admin ci
npm --prefix src/SignaCore.Admin run build
```

## Architecture

The host composes `SignaCore.Domain`, `SignaCore.Database`, and the provider-specific migration projects. Domain code must not depend on ASP.NET Core transport types. Downstream systems integrate through HTTP discovery, JWKS, and APIs; they do not reference repository assemblies.

## Conventions

- Use the `SignaCore` root namespace and matching project/assembly names.
- Keep public routes, JSON fields, claims, and existing database table names stable unless an intentional migration is designed.
- Propagate cancellation tokens and use UTC timestamps.
- Never commit or log credentials, application secrets, OTP values, refresh tokens, authorization headers, private signing keys, or master keys.
- Add unit coverage for policy changes and integration/contract coverage for HTTP or provider behavior.
- Update English documentation whenever behavior or configuration changes.

## Persistence

PostgreSQL migrations are in `SignaCore.Database`; MySQL/MariaDB migrations are in `SignaCore.Database.Migrations.MySql`; SQLite migrations are in `SignaCore.Database.Migrations.Sqlite`. A schema change must account for all three migration histories.

## Deployment identifiers

The canonical product is `SignaCore`; the local image and container are `signacore`; the Consul prefix is `config/signacore`; the default JWT issuer is `SignaCore`; and the default audience is `SignaCore.Services`.
