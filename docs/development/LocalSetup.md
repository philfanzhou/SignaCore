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

Override nested settings with double underscores, for example `Database__ConnectionString` and `Jwt__Issuer`. Store secrets in environment variables or .NET user secrets.

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
