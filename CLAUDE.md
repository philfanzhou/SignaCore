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
- Never name a specific consumer. Documentation, comments, and commit messages describe downstream systems by role — the calling application, the business system, a staff-facing application — never by product name, brand, repository link, or their validator configuration. This repository is public, so naming one leaks another party's integration details; and SignaCore is a general-purpose identity service, so naming one consumer makes the contract read like a bespoke one. Use a neutral placeholder when an example is needed (`OrderService`). This does not cover SignaCore's own deployment identifiers, which are real configuration contract.
- Add unit coverage for policy changes and integration/contract coverage for HTTP or provider behavior.
- Update English documentation whenever behavior or configuration changes.

## Configuration

Global application configuration lives in the business database (`system_settings`) and is managed
through first-run setup and the authenticated administration pages. Only the database
provider/version/connection and the inline external root key live outside it, in the writable,
protected bootstrap file at `<application-base>/config/signacore.bootstrap.json`. The file is
created or replaced atomically by protected UI workflows. A new database-backed setting is added
to the catalog in `SignaCore.Host/Configuration/SystemSettingsCatalog.cs`, with a safe product
default and an explicit secret flag; it is not added to `appsettings.json`. Consul KV is not a
configuration source.

## Persistence

PostgreSQL migrations are in `SignaCore.Database`; MySQL/MariaDB migrations are in `SignaCore.Database.Migrations.MySql`; SQLite migrations are in `SignaCore.Database.Migrations.Sqlite`. A schema change must account for all three migration histories.

## Deployment identifiers

The canonical product is `SignaCore`; the local image and container are `signacore`; the Consul
service name for optional discovery is `SignaCore`; the JWT issuer is the canonical public base URL
collected by first-run setup; and the default audience is `SignaCore.Services`.
