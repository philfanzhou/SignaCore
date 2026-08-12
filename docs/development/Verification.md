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

Issue a token with a test application, confirm `iss` matches the configured HTTPS issuer and
`aud=SignaCore.Services` (or the application's per-application audience), verify its RS256 signature
from JWKS, exercise refresh rotation, and confirm migration history in the selected database.

CI runs the full integration project, verifies refresh rotation/replay rejection and digest-only
storage against the containerized PostgreSQL smoke deployment, blocks high/critical fixed container
vulnerabilities, uploads an SPDX JSON SBOM, and runs CodeQL for C# and JavaScript/TypeScript.

## Rename audit

```bash
rg -i 'former-product-token' . --hidden -g '!**/.git/**' -g '!**/bin/**' -g '!**/obj/**'
```

Also inspect artifact names, container metadata, log labels, dashboards, Consul registrations, and downstream issuer/audience configuration.
