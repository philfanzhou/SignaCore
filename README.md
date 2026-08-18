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
- PostgreSQL and SQLite through EF Core provider-specific migrations
- Database-backed global configuration with web-based first-run setup
- Optional Consul service discovery
- OpenTelemetry, Prometheus, Serilog, and optional Loki export

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/SignaCore.Database` | EF Core model, repositories, and PostgreSQL migrations |
| `src/SignaCore.Database.Migrations.*` | SQLite migration assembly |
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

Point `appsettings.Development.json` at a local PostgreSQL instance (or override
`Database__ConnectionString`), then run:

```bash
dotnet run --project src/SignaCore.Host/SignaCore.Host.csproj
```

The first run against an empty database enters Setup Mode. Open `/setup`, enter the one-time setup
code printed to the console, and supply the public base URL and administrator credentials. See
[first-run setup](docs/development/FirstRunSetup.md).

The API listens on the URLs in `src/SignaCore.Host/Properties/launchSettings.json`. Useful endpoints include `/health/live`, `/health/ready`, `/.well-known/openid-configuration`, `/.well-known/jwks` (also reachable as `/.well-known/jwks.json`), `/metrics`, `/oauth2/token`, `/api/auth/token`, and `/admin`.

## Container

```bash
IMAGE_TAG=latest ./build.sh

mkdir -p config
chmod 700 config

./start.sh
```

On first start, open `/bootstrap` and enter the one-time code printed by `docker logs signacore`.
The protected UI tests the database, generates the root key for a new install, and atomically creates
`config/signacore.bootstrap.json`. The directory is mounted read-write so later authenticated edits
can replace the file. Everything else is configured through first-run setup and administration
pages. A brand-new installation stays live but not ready during both configuration phases, and the
launcher reports that instead of rolling back.

## Configuration

Global application configuration lives in the business database, in `system_settings`. Every instance
reads the same active configuration, changes are transactional and audited, and there is no
per-instance drift.

Only what is required to open and decrypt that database stays outside it, in one writable bootstrap
file at `/app/config/signacore.bootstrap.json`: the database provider, server version, and connection
string, plus the inline external root key. The whole file is a mode-`0600` secret on persistent
storage and must be backed up with the database.

Important defaults, all stored in the database and editable after installation:

| Setting | Default |
| --- | --- |
| `Endpoints:PublicBaseUrl` | collected by first-run setup |
| `Jwt:Issuer` | the normalized public base URL |
| `Jwt:Audience` | `SignaCore.Services` |
| `Consul:Discovery:Enabled` | `false` |
| `APP_TITLE` (launcher) | `SignaCore` |

See [configuration](docs/development/Configuration.md) for the full catalog.

## Rename migration

The rename changes .NET namespaces and assembly names from the former product name to `SignaCore.*`. It also changes the default image/container, database name, Consul service/prefix, JWT issuer/audience, telemetry source, and UI package name. Existing deployments should override old JWT values during a rolling migration if previously issued tokens must remain valid, point the bootstrap connection string at the existing database if data must be retained, and reuse the previous `RSA_MASTER_KEY` value as the bootstrap root key so stored signing keys remain decryptable. Database table names and HTTP contracts were not renamed.

## Documentation

Start with [the documentation index](docs/README.md), [system design](docs/overview/Design.md), [configuration](docs/development/Configuration.md), and [deployment](docs/development/Deployment.md). Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md), and vulnerabilities should be reported through [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
