# Contributing to SignaCore

Thank you for improving SignaCore. Keep changes focused, preserve public contracts unless the change is explicitly breaking, and write contributor-facing text in English.

## Development workflow

1. Create a branch from `main`.
2. Restore and build the root solution.
3. Add or update tests for behavior changes.
4. Update documentation and configuration examples when behavior changes.
5. Open a pull request describing the problem, the approach, compatibility impact, and verification performed.

```bash
dotnet restore SignaCore.slnx
dotnet build SignaCore.slnx --configuration Release
dotnet test tests/SignaCore.Tests/SignaCore.Tests.csproj --configuration Release
dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj --configuration Release
npm --prefix src/SignaCore.Admin ci
npm --prefix src/SignaCore.Admin audit --audit-level=high
npm --prefix src/SignaCore.Admin run test:coverage
npm --prefix src/SignaCore.Admin run build
```

Docker is required for the complete database contract matrix and image smoke checks.

## Project boundaries

Downstream systems integrate with SignaCore over HTTP (Discovery, JWKS, and the documented API
and OAuth surfaces) or by referencing the officially released client package
`SignaCore.Client.AspNetCore`; see
[ADR 0007](docs/adr/0007-official-hosted-login-client-package.md). Server-side assemblies (`SignaCore`
host, `SignaCore.Domain`, `SignaCore.Database`, and the migration projects) are never published for
downstream reference, and contributions to the client package must not add consumer business
models, branding, or authorization rules.

## Database changes

Schema changes must include reviewed migrations for PostgreSQL and SQLite. Keep existing migration identifiers intact and verify each provider's contract tests.

## Security

Do not open public issues for vulnerabilities or include live secrets in tests, logs, screenshots, or pull requests. Follow [SECURITY.md](SECURITY.md) for private reporting.
