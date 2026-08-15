# Local Setup

## Prerequisites

- .NET SDK 10
- Node.js 20.19+ or 22.12+ and npm
- PostgreSQL for the default profile; MySQL/MariaDB or SQLite may be selected instead
- Docker for image and smoke-test verification

## Backend

```bash
dotnet restore SignaCore.slnx
dotnet build SignaCore.slnx
dotnet run --project src/SignaCore.Host/SignaCore.Host.csproj
```

The database connection comes from the writable protected bootstrap file. In Development only, when
`config/signacore.bootstrap.json` is absent, the `Database` section of `appsettings.Development.json`
is used instead, so a clone-and-run setup works without preparing a secret file. Override it with
`Database__ConnectionString` if your local database differs.

Everything else — public base URL, issuer, SMS, WeChat, LDAP — lives in the database. The first run
against an empty database enters Setup Mode: open `http://localhost:5002/setup` and enter the
one-time setup code printed to the console. See [First-run setup](./FirstRunSetup.md).

To exercise the production bootstrap path locally, create
`src/SignaCore.Host/bin/Debug/net10.0/config/signacore.bootstrap.json`, or point `Bootstrap__FilePath`
at a file elsewhere.

## Admin frontend

```bash
npm --prefix src/SignaCore.Admin ci
npm --prefix src/SignaCore.Admin run dev
npm --prefix src/SignaCore.Admin run build
```

The Vite development server proxies API requests to the configured backend. Production assets are built into the host image.

## Tests

```bash
dotnet test tests/SignaCore.Tests/SignaCore.Tests.csproj
dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj
```
