# Verification

## Fast checks

```bash
dotnet build SignaCore.slnx --configuration Release
dotnet test tests/SignaCore.Tests/SignaCore.Tests.csproj --configuration Release
npm --prefix src/SignaCore.Admin ci
npm --prefix src/SignaCore.Admin audit --audit-level=high
npm --prefix src/SignaCore.Admin run test:coverage
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
curl --fail http://localhost:5002/health/live
curl --fail http://localhost:5002/api/bootstrap/status
```

With an empty configuration directory, the service reports `"status":"required"`, serves
`/bootstrap`, keeps readiness false, and returns `503 bootstrap_configuration_required` from normal
APIs. Confirm a wrong/expired code and invalid database target do not create the file. Complete the
protected bootstrap form and verify the resulting JSON has only `Database` and inline `MasterKey`,
with mode `0600`.

After restart, a new empty database reports `"status":"pending"` from `/api/setup/status`, serves
`/setup`, and returns
`503 installation_required` from every other API. Complete setup with the one-time code from the
container log, wait for the container to restart, then verify the normal surface:

```bash
curl --fail http://localhost:5002/health/ready
curl --fail http://localhost:5002/health
curl --fail http://localhost:5002/.well-known/openid-configuration
curl --fail http://localhost:5002/.well-known/jwks
curl --fail http://localhost:5002/.well-known/jwks.json
curl --fail http://localhost:5002/metrics
```

Issue a token with a test application, confirm `iss` matches the configured HTTPS issuer and
`aud=SignaCore.Services` (or the application's per-application audience), verify its RS256 signature
from JWKS, exercise refresh rotation, and confirm migration history in the selected database.

CI runs the full integration project, verifies refresh rotation/replay rejection and digest-only
storage against the containerized PostgreSQL smoke deployment, blocks high/critical fixed container
vulnerabilities, uploads an SPDX JSON SBOM, and runs CodeQL for C# and JavaScript/TypeScript. Unit
test coverage is collected with Microsoft Testing Platform after excluding generated migrations and
test assemblies; CI enforces a 45% line and branch baseline. The frontend coverage command enforces
its own checked-in baseline in `vitest.config.ts`.

## Rename audit

```bash
rg -i 'former-product-token' . --hidden -g '!**/.git/**' -g '!**/bin/**' -g '!**/obj/**'
```

Also inspect artifact names, container metadata, log labels, dashboards, Consul registrations, and downstream issuer/audience configuration.

## Configuration audit

Startup logs any deployment-provided value for a database-backed setting, and any `Database` section
outside the bootstrap file, as an ignored legacy override. A clean deployment produces neither
warning.
