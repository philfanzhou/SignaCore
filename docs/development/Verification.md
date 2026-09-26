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

### Required OIDC matrix result gate

The `Database Contract Matrix` job runs for pull requests targeting `main` and pushes to `main`,
after `Build & Test`. `Protect main` requires this exact check name. The job has a **25-minute hard
timeout** and enables PostgreSQL contracts with `RUN_SIGNACORE_DATABASE_CONTRACTS=true`. Its existing
filter includes `DatabaseContractTests` plus the installation-adoption and migration-gate exceptions;
the reference BFF contracts run in a separate step of the same job.

After the test steps, the Python standard-library
[result validator](../../.github/scripts/verify_oidc_matrix.py) requires exactly one readable report
for each of `signacore-database-contracts.trx` and
`signacore-reference-bff-database-contracts.trx` under `reports/`. It checks result/definition
correspondence, unique result IDs, successful run summaries and consistent execution counters.
Every reported test must pass. Missing, duplicate, malformed or incomplete reports fail the job.

The integration report must also contain exactly the checked-in
[OIDC case inventory](../../.github/scripts/oidc-matrix-cases.json), including theory arguments:

| Test class | Expected passed cases |
| --- | ---: |
| `OidcAttackRateLimitDatabaseContractTests` | 30 |
| `OidcSensitiveCanaryMatrixDatabaseContractTests` | 13 |
| `OidcNamedRevocationDatabaseContractTests` | 5 |

Missing classes/cases, unexpected or repeated cases, skipped/not-executed cases and failures cannot
produce a successful gate. Update the inventory in the same PR as any intentional change to these
tests, after reviewing the changed cases; do not lower expectations just to make a failed run pass.
Validator diagnostics contain only known class names, counts and fixed statuses, never report test
output, case arguments, exception details or Canary values.

Run the synthetic positive/negative acceptance tests without containers:

```bash
python3 -m unittest discover -s .github/scripts -p 'test_verify_oidc_matrix.py' -v
python3 .github/scripts/verify_oidc_matrix.py reports
```

CI runs these self-tests before the database tests. The validator runs after a test failure as well
as after success, but does not run on cancellation. The existing `if: always()` artifact upload
preserves available reports for diagnosis; it cannot turn a failed or cancelled job into success.
Only synthetic test data belongs in uploaded reports; never include live credentials or tokens.

There are **zero automatic retries of test assertion failures**. Diagnose the first failed run and
retain its evidence before any manual rerun. `docker-pull.sh` permits at most three pull attempts
only for recognized transient registry/network failures; it does not retry tests. Runner, registry
and PostgreSQL availability are outside the result gate's guarantee. For a gate change, record the
actual PR job duration and inspect its uploaded TRX, then repeat that verification on the post-merge
`main` run. Historical green runs and local self-tests do not replace those CI acceptance results.

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

After restart, a new empty database reports `"status":"pending"` from `/management/v1/setup`, serves
`/setup`, and exposes no identity endpoint: reads of other APIs are `404`, and writes are the
shared phase gate's `503 service.phase.unavailable`. Complete setup with the one-time code from the
container log by posting
`{"code":"...","input":{"publicBaseUrl":...,"allowNonHttpsIssuer":false,"jwtAudience":...,
"username":...,"password":...}}` with the `X-ServiceMantle-Request: 1` header; a wrong code is
answered `401`, success is `204`, and a replay against the restarted host is `409`. Wait for the
container to restart, then verify the normal surface:

```bash
curl --fail http://localhost:5002/health/ready
curl --fail http://localhost:5002/health
curl --fail http://localhost:5002/.well-known/openid-configuration
curl --fail http://localhost:5002/.well-known/jwks
curl --fail http://localhost:5002/.well-known/jwks.json
curl --fail -H "X-Admin-AppId: $SCRAPER_APP_ID" -H "X-Admin-AppSecret: $SCRAPER_APP_SECRET" \
  http://localhost:5002/metrics
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
