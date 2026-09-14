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

## Database changes

Schema changes must include reviewed migrations for PostgreSQL and SQLite. Keep existing migration identifiers intact and verify each provider's contract tests.

## Security

Do not open public issues for vulnerabilities or include live secrets in tests, logs, screenshots, or pull requests. Follow [SECURITY.md](SECURITY.md) for private reporting.
