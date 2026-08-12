# SignaCore

SignaCore is a .NET 10 identity and authentication service. It centralizes account authentication, issues RS256 JWTs, rotates refresh tokens, exposes JWKS discovery, and provides an administrative Vue console.

## Capabilities

- Password, SMS, WeChat, LDAP, and refresh-token grants
- Per-application admission policies for SMS, LDAP, and WeChat, with self-service WeChat binding
- RFC 6749 token endpoint and RFC 7009 revocation at /oauth2/*, alongside the legacy /api/auth/* contract
- Per-application access-token audience isolation
- RS256 signing-key generation, encrypted private-key storage, rotation, and JWKS publication
- Application registration, callback claim enrichment, and gateway authentication
- User/profile administration, audit trails, login history, lockout, and cleanup jobs
- PostgreSQL, MySQL/MariaDB, and SQLite through EF Core provider-specific migrations
- Consul KV configuration and service discovery with local-cache fallback
- OpenTelemetry, Prometheus, Serilog, and optional Loki export

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/SignaCore.Database` | EF Core model, repositories, and PostgreSQL migrations |
| `src/SignaCore.Database.Migrations.*` | MySQL/MariaDB and SQLite migration assemblies |
| `src/SignaCore.Domain` | Authentication, token, key, SMS, LDAP, and audit logic |
| `src/SignaCore.Host` | ASP.NET Core host, HTTP API, SPA hosting, and Dockerfile |
| `src/SignaCore.Admin` | Vue 3 administrative console |
| `tests` | Unit and integration/contract test projects |
| `docs` | Architecture, operations, schema, and feature documentation |
| `.github` | GitHub Actions, dependency automation, and contribution templates |

## Build and test

Requirements: .NET SDK 10, Node.js 20.19+ or 22.12+ with npm for the admin UI, and Docker for the container smoke test.

```bash
dotnet restore SignaCore.slnx
dotnet build SignaCore.slnx --configuration Release
dotnet test tests/SignaCore.Tests/SignaCore.Tests.csproj
dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj
npm --prefix src/SignaCore.Admin ci
npm --prefix src/SignaCore.Admin run build
```

## Run locally

Provide a PostgreSQL connection string and development secrets through user secrets or environment variables, then run:

```bash
dotnet run --project src/SignaCore.Host/SignaCore.Host.csproj
```

The API listens on the URLs in `src/SignaCore.Host/Properties/launchSettings.json`. Useful endpoints include `/health`, `/.well-known/openid-configuration`, `/.well-known/jwks`, `/metrics`, `/oauth2/token`, `/api/auth/token`, and `/admin`.

## Container

```bash
IMAGE_TAG=latest ./build.sh
ADMIN_BOOTSTRAP_PASSWORD='replace-me' \
RSA_MASTER_KEY='long-random-secret-from-secret-manager' \
JWT_ISSUER='https://identity.example.com' \
PUBLIC_BASE_URL='https://identity.example.com' \
DATABASE_CONNECTION_STRING='Host=db;Database=signacore;Username=signacore;Password=replace-me' \
SMS_BYPASS_CODE='' \
SMS_BYPASS_PHONES='' \
SMS_OTP_HMAC_KEY='base64-encoded-key' \
./start.sh
```

The default image is `signacore:latest` and the default container name is `signacore`. The launcher
resolves the tag to an immutable image ID, waits for `/health`, and restores the previous container if
the new instance fails. Secrets must come from the deployment environment or a secret manager; never
commit them.

## Configuration

ASP.NET Core configuration precedence applies. SignaCore additionally loads Consul KV under `config/signacore`, with local cache and appsettings fallback. Important defaults are:

| Setting | Default |
| --- | --- |
| `Jwt:Issuer` | `SignaCore` |
| `Jwt:Audience` | `SignaCore.Services` |
| `Database:Provider` | `PostgreSQL` |
| `Database:ConnectionString` | local development value only |
| `Consul:ServiceName` | `SignaCore` |
| `Consul:KvPrefix` | `config/signacore` |
| `APP_TITLE` | `SignaCore` |

## Rename migration

The rename changes .NET namespaces and assembly names from the former product name to `SignaCore.*`. It also changes the default image/container, database name, Consul service/prefix, JWT issuer/audience, telemetry source, and UI package name. Existing deployments should override old JWT values during a rolling migration if previously issued tokens must remain valid, copy Consul KV to the new prefix, and point the new connection string at the existing database if data must be retained. Database table names and HTTP contracts were not renamed.

## Documentation

Start with [the documentation index](docs/README.md), [system design](docs/overview/Design.md), [configuration](docs/development/Configuration.md), and [deployment](docs/development/Deployment.md). Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md), and vulnerabilities should be reported through [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
