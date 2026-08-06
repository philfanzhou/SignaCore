# Verification

## Fast checks

```bash
dotnet build SignaCore.slnx --configuration Release
dotnet test tests/SignaCore.Tests/SignaCore.Tests.csproj --configuration Release
npm --prefix src/SignaCore.Admin ci
npm --prefix src/SignaCore.Admin audit --audit-level=high
npm --prefix src/SignaCore.Admin run build
```

## Integration and database contracts

```bash
dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj --configuration Release
```

Server database contract tests use environment-supplied connection strings. CI runs the supported provider matrix and uploads test results.

## Container smoke test

After starting the container, verify:

```bash
curl --fail http://localhost:5002/health
curl --fail http://localhost:5002/.well-known/openid-configuration
curl --fail http://localhost:5002/.well-known/jwks
curl --fail http://localhost:5002/metrics
```

Issue a token with a test application, confirm `iss=SignaCore` and `aud=SignaCore.Services`, verify its RS256 signature from JWKS, exercise refresh rotation, and confirm migration history in the selected database.

## Rename audit

```bash
rg -i 'former-product-token' . --hidden -g '!**/.git/**' -g '!**/bin/**' -g '!**/obj/**'
```

Also inspect artifact names, container metadata, log labels, dashboards, Consul registrations, and downstream issuer/audience configuration.
