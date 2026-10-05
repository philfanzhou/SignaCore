# Deployment

Current database support is PostgreSQL 15+ and local-file SQLite (single-instance). Candidate
MySQL, MariaDB, SQL Server and Oracle deployments remain deferred under the
[database provider support decision](../database/provider-support-decision.md).

## Build

```bash
IMAGE_TAG=latest ./build.sh
```

This produces `signacore:latest` from `src/SignaCore.Host/Dockerfile`. The image builds the Vue admin application, restores and publishes `SignaCore.Host`, runs as the non-root `app` user, exposes port 5002, and starts `SignaCore.Host.dll`.

### Where base images come from

The .NET stages pull from Microsoft's container registry. Default local builds keep the official
multi-platform Node `24-alpine` tag from the AWS public mirror
(`public.ecr.aws/docker/library/`). The Dockerfile has no `syntax` directive, which avoids an
additional Docker Hub frontend pull. Both AWS Public ECR and Docker Hub impose anonymous quotas;
shared runner egress can exhaust them even when a change is correct.

The final stage also runs a targeted `apt-get install --only-upgrade` of the Ubuntu `openssl` and
`libssl3t64` packages to clear CVE-2026-84782 from the floating `aspnet:10.0` tag. Only these two
packages are upgraded; once the base image carries the fixed version the step becomes a no-op, and
the CI Trivy gate remains the independent guard.

CI uses `.github/scripts/resolve_official_image.py` with the fixed `node` or `postgres` profile.
It pulls Linux/amd64 content from AWS first, then the corresponding `docker.io/library/` official
repository only after two transient failures. Each source has at most two attempts, each pull has
a 180-second timeout, and retries wait five seconds. Missing manifests, invalid references,
unknown errors, or content/platform validation failures stop immediately. Cancellation stops
without publishing a reference. Both sources failing still fails the original check.

The profiles pin the same platform manifest digest across both sources:

| Profile | Tag | Linux/amd64 manifest digest |
| --- | --- | --- |
| Node | `24-alpine` | `sha256:83f1c388c31fb2e51f7cbd4dea949b96260798c98f206e8e4696bc93bd964e3a` |
| PostgreSQL | `15-alpine` | `sha256:25d430274d8a31184f9435cc5b2f56aff254952065bbbcac0c51acedb5a1d1e7` |

Maintainers must verify that both official sources contain identical content for the stated
version and platform before updating these pins and the Node allowlist in `build.sh`.
Docker validates the digest during pull; inspection also verifies the repository digest and
Linux/amd64 platform. Only the successful `repository:tag@digest` reference is exported.
`SIGNACORE_NODE_IMAGE` passes that fixed official reference through `build.sh` into the Dockerfile's
`NODE_IMAGE` build argument. Unlisted overrides are rejected. An ordinary `IMAGE_TAG=latest
./build.sh` invocation requires no resolver or override and retains its default platform behavior.
Each CI job independently exports `SIGNACORE_POSTGRES_IMAGE`; container smoke and all integration
and Reference BFF Testcontainers consume that same warmed reference. Local tests fall back to the
plain official Docker Hub tag when the variable is absent.

This recovery adds no runtime business configuration, credentials, database migration, or change
to required checks, scanning, SBOM, smoke, and real database contracts. Reverting the recovery
change and this documentation restores the single-source CI behavior, including its quota failures.
It cannot guarantee that either anonymous registry is always available.

The release job's BuildKit builder image still comes from Docker Hub on default-branch pushes and
release tags. This recovery does not change that publishing path; pull requests never reach it.

## The `edge` image

Every push to the default branch that passes the full pipeline publishes
`ghcr.io/philfanzhou/signacore:edge`. The tag moves to the newest such commit, so it names whatever
the default branch currently is — not a release. Use it for development environments and for
verifying a change in a real container; never pin a deployment to it, because the digest behind it
changes without notice.

Each push leaves the previously tagged manifest, together with its provenance and SBOM attestations,
as an untagged version of the package. GHCR does not remove those, so the untagged versions
accumulate and are pruned by hand when they become inconvenient.

## Releasing

Releases are driven entirely by pushing a tag. No release is published by hand.

```bash
git tag -a 0.1.4 -m "SignaCore 0.1.4"
git push origin 0.1.4
```

Release candidates use the same process with an `-rc.NUMBER` suffix:

```bash
git tag -a 0.1.8-rc.1 -m "SignaCore 0.1.8-rc.1"
git push origin 0.1.8-rc.1
```

The tag must use `MAJOR.MINOR.PATCH` or `MAJOR.MINOR.PATCH-rc.NUMBER`; CI rejects anything else.
Pushing it runs the full
pipeline — build, unit tests, integration and HTTP contract tests, the image vulnerability scan, the
containerised first-run and smoke assertions, and the database contract matrix — and only if all of
it passes does the release happen, in two steps:

1. **Publish GHCR Image** builds and pushes `ghcr.io/philfanzhou/signacore` with provenance and an
   SBOM attached. A stable release updates the exact version, the `MAJOR.MINOR` line, and `latest`.
   A release candidate publishes only its exact immutable version and never moves either stable
   channel.
2. **Publish GitHub Release** creates the release for the tag, quoting the digest that was actually
   published and appending GitHub's generated changelog. Release candidates are marked as GitHub
   pre-releases; stable versions are marked latest.

Because the release job runs last, a release only ever exists for a tag whose tests passed and whose
image is pullable. A tag whose pipeline fails publishes neither; fix the cause, then tag a new
version rather than moving the failed tag.

Re-running the workflow for a tag that already has a release leaves that release untouched, so notes
edited afterwards are never overwritten.

## Prepare persistent bootstrap storage

The launcher no longer carries application secrets. Everything except the database connection and the
external root key lives in the business database and is managed through first-run setup and the
administration pages.

Create a persistent directory next to `start.sh` and make it writable only by the container runtime
identity:

```bash
mkdir -p ./config
chmod 700 ./config
```

On the first start, leave the directory empty. SignaCore stays live, prints a one-time bootstrap
credential to standard output, and serves `/bootstrap`. The protected form tests the database and
creates this exact file atomically, generating the master key for a new installation. Restarting
SignaCore issues a new credential and invalidates the previous one:

```json
{
  "Database": {
    "Provider": "PostgreSQL",
    "ServerVersion": "15",
    "ConnectionString": "Host=db;Database=signacore;Username=signacore;Password=replace-me"
  },
  "MasterKey": "generated-cryptographically-random-root-key"
}
```

For migration or recovery, select existing installation and submit the existing key as a write-only
value. There is no separate master-key file. Losing the resulting bootstrap file means protected RSA
private keys and secret settings become undecryptable; back it up with the database.

See [Configuration](./Configuration.md#bootstrap-file) for the full schema.

## Run

`start.sh` defaults to image `signacore:latest` and container `signacore`:

```bash
./start.sh
```

The script mounts `./config` read-write at `/app/config` and `./data` at `/app/data`, where bootstrap
applications and other mutable runtime data may be stored. It resolves the requested tag to its image
ID before changing containers, waits for `/health/live`, then waits for `/health/ready`, and restores
the previous container automatically when startup, health verification, or the deployment script
itself fails or is interrupted. `curl` is required on the deployment host.

With no bootstrap file, readiness stays false until an operator completes `/bootstrap`; an empty
database then enters `/setup` and remains not ready until first-run setup completes. The launcher
recognizes both states and keeps the container running instead of rolling back. See
[First-run setup](./FirstRunSetup.md).

The launcher gives the old container 35 seconds to shut down cleanly. A rollback restores the prior
container image and configuration, but it does not reverse database migrations; keep migrations
backward-compatible and take a verified database backup before deployment.

Startup uses one core-only ServiceMantle container for the preparation and migration stages.
It registers no hosted services or startup identity. Preparation runs before the historical outer
initialization lock; the legacy pre-check runs inside that lock before migration, then installation
resolution follows. Each migration run has a fresh receipt and explicitly skips preparation;
the caller retains ownership of its executor and DbContext. Shared preparation owns the only
observe/create/confirm sequence. The product preserves fixed provider error classifications from
its invocation-local observations, and delegates an initially dirty SQLite target to EF's native
open without enabling shared WAL checkpointing. No target creation or committed migration is
rolled back by a later failure or cancellation.

Startup prepares a missing PostgreSQL database target through the shared ServiceMantle preparation
provider (see [First-run setup](./FirstRunSetup.md#database-target-preparation-at-startup)). An
already-connectable target is used as-is without any maintenance-database access; a missing target
is created as an ordinary PostgreSQL database owned by the configured role, so a rollback to an
older binary keeps reading it unchanged. Start failures on the preparation step are reported with
the fixed closed classifications (for example authentication or connection failures) instead of raw
driver errors, and never include the connection string or credentials.

On SQLite, startup prepares the file target through the shared ServiceMantle preparation provider
under a narrowed path contract (see
[First-run setup](./FirstRunSetup.md#sqlite-target-preparation-and-the-absolute-path-contract)):
the `Data Source` must be a platform-absolute canonical file path. Deployments that completed first
install already satisfy this; a hand-edited bootstrap file naming a relative path, a
`|DataDirectory|` form, or a `file:` URI must be corrected to an absolute path during upgrade, or
the new version refuses to start with a fixed message. The preparation provider creates a missing
target as an ordinary SQLite file an older binary keeps reading after a rollback; existing
WAL-mode databases keep their journal mode. Start failures on the preparation step are reported
with fixed closed classifications and never include the connection string.

The launcher owns only deployment concerns, overridable through the environment:

| Variable | Default | Purpose |
| --- | --- | --- |
| `IMAGE_NAME`, `IMAGE_TAG` | `signacore:latest` | Image to deploy |
| `CONTAINER_NAME` | `signacore` | Container name |
| `PORT` | `5002` | Host port |
| `CONFIG_DIR` | `./config` | Writable persistent bootstrap mount |
| `DATA_DIR` | `./data` | Mutable data mount |
| `TZ` | `Asia/Shanghai` | Container timezone |
| `APP_TITLE` | container name | Admin console and document title |

## Health endpoints

| Endpoint | Meaning | Used by |
| --- | --- | --- |
| `/health/live` | The process is running; once configured, database liveness is also checked | Launchers deploying a new instance, so bootstrap/setup pages can be reached |
| `/health/ready` | Installation is completed, the configuration snapshot is valid, database initialization is complete, and signing keys are ready | Load balancers and orchestrators |
| `/health` | Compatibility alias for readiness | Existing checks |

A pending-setup instance is live but not ready, so it never receives authentication traffic.

## Production checklist

- Choose HTTPS at the service or a trusted reverse proxy when transport confidentiality is
  required. HTTP sends management passwords and Bearer credentials in plaintext; SignaCore does
  not force HTTPS for management routes.
- Prepare the writable persistent bootstrap directory, complete protected bootstrap configuration,
  restrict the resulting file to mode `0600`, and back it up.
- Set `reverse_proxy.known_proxies` through the authenticated settings page when TLS terminates at
  a non-loopback proxy; the legacy projection is `ReverseProxy:KnownProxies`. The activated
  database snapshot alone supplies this business setting. See the [proxy trust boundary](#proxy-trust-boundary).
- The built-in console uses a 15-minute in-memory management Bearer and requires sign-in after a
  page reload. Its requests omit Cookie credentials. Preserve its one Bearer header on supported
  management routes; do not add an `Authorization` header to Cookie clients' requests, since a
  request carrying one selects Bearer and ignores the Cookie (see
  [Management bearer authentication](./ManagementBearerSessionSchema.md#authentication-scheme)).
- Use a production database and verify the selected provider's migrations.
- Complete first-run setup and record the administrator credentials in your secret manager.
- Set the JWT audience expected by downstream services; the issuer follows the public base URL.
- Publish `/.well-known/openid-configuration` and JWKS through the public base URL.
- Point orchestrator and Consul health checks at `/health/ready`.
- When Consul registration is enabled, set `Consul:Discovery:Deregister=true` and give every
  instance its own `ServiceDiscovery:Address` / `ServiceDiscovery:Port` (environment variables
  `ServiceDiscovery__Address` / `ServiceDiscovery__Port`); a non-loopback Consul agent must be
  reached over HTTPS. Registration changes take effect after a restart — see
  [Consul integration](./ConsulIntegration.md).
- Scrape `/metrics` with a dedicated registered application's `X-Admin-AppId` / `X-Admin-AppSecret`
  headers (see [Configuration](./Configuration.md#metrics-and-traces)) and connect logs/traces to
  the chosen observability backend; an OTLP collector must be reached over HTTPS.
- Remove legacy application-setting environment variables from the launcher; startup logs any that
  remain.
- Run the verification steps after deployment.

## Shared OIDC rate limits

On PostgreSQL, every replica counts the interactive OIDC rate limits in one shared database budget
(see the [OIDC security contract](../oidc/Security.md#rate-limit-contract)). All replicas must use
the same database, the same bootstrap root key, and the same release:

- Upgrade and roll back all replicas together. A replica of an older release keeps a per-process
  budget, so while versions are mixed the cross-replica budget does not hold.
- Changing the root key resets every shared budget.
- Each protected OIDC request runs one short database statement. Size the database connection
  capacity for it; when the database cannot answer within 2 seconds those requests receive `503`.

SQLite deployments are single-instance and keep an in-process budget.

## Backup and recovery

Two artifacts must be backed up together, because they are only useful as a set:

1. the business database, which now holds global configuration alongside identity data;
2. the bootstrap file, which names the database and contains the external root key.

Restoring the database without the matching root key leaves stored signing keys and secret settings
undecryptable. Startup fails closed in that case, naming the affected setting keys — it does not
silently rotate or replace signing keys.

## Upgrading a pre-bootstrap deployment

1. Build and distribute the new image.
2. Create the bootstrap file using the currently deployed connection string and the value the
   deployment previously supplied as `RSA_MASTER_KEY`. The key derivation is unchanged, so stored
   signing keys remain decryptable.
3. Leave the existing legacy environment variables in place for one start. Migrations bring the
   schema up to date and adopt the database into the shared `service_installations` installation
   state, and because business data already exists SignaCore runs the protected legacy import instead
   of exposing `/setup`.
4. Confirm startup reported a completed import, then remove the legacy variables from the launcher and
   redeploy. Anything still supplied is logged as an ignored legacy override.
5. Change settings from then on through the administration pages, followed by a coordinated rolling
   restart.

## Minimum supported upgrade version

The oldest supported direct upgrade source is SignaCore `0.1.1`. That release introduced one-way
digests for stored refresh tokens and converted existing plaintext values during startup. Current
startup no longer performs that one-time plaintext-to-digest conversion.

Before upgrading a deployment older than `0.1.1`, clear all rows from `refresh_tokens`. Existing
sessions will no longer be refreshable, so users must sign in again after the upgrade. The table
schema and refresh-token digest format are unchanged.

# Public browser Origins

Administrators register exact Origins on active Public applications through the authenticated
management API. `POST /oauth2/token` and `GET /oauth2/userinfo` admit only the matching
application's registered Origin on actual responses. Preflights check the active Public Origin
union and the endpoint's exact method and header. The AdminWeb allow list does not apply to
`/oauth2`; no Public Origin permits authorization, revoke, or logout. A token response is
readable for Code redemption and refresh rotation alike, and only after client authentication has
selected that application. Keep browser
credentials out of cookies and use HTTPS, PKCE, and a suitable script isolation policy.

Public Code refresh is an explicit per-application opt-in. It requires a 1–43200-second session
maximum age and `offline_access`; the family ends at the earliest of seven days, the original
session absolute expiry, or that application maximum age. Use HTTPS,
isolate scripts, retain bearer tokens in memory for the shortest practical time, and clear them
on logout; high-privilege administration should prefer a confidential BFF. Rolling back to a
binary without `sha256-public:` family support requires affected Public clients to sign in again.
Already-issued self-contained JWTs remain valid until their own `exp`. Rolling back to a binary
without refresh CORS only removes the Origin header from refresh responses; issued tokens and
family state are unaffected and no data migration is needed.

A Public client's sign-out only clears its own page: it cannot revoke the refresh family or end the
SignaCore identity session, so the family stays valid until its bounded expiry and a new sign-in may
not prompt. On shared devices an administrator revokes the identity session, or the browser is
closed. The [Public SPA sample](../../samples/SignaCore.PublicSpa/README.md) shows the complete
registration order and these limits.

## Proxy trust boundary

Only the normal host activates ServiceMantle forwarding, once inside the shared pipeline and
before rate limiting/authentication. It preserves the previous ASP.NET Core trust defaults:
IPv6 loopback `::1` and IPv4 loopback network `127.0.0.0/8`, plus the explicitly configured proxy
addresses. Equivalent addresses are normalized and deduplicated; invalid input fails startup
with a fixed safe diagnostic, without echoing the supplied address. It processes one rightmost
hop of symmetric `X-Forwarded-For`/`X-Forwarded-Proto` headers. Missing or asymmetric headers are
ignored. `X-Forwarded-Host` remains disabled, so it cannot change the request Host.

Unconfigured remote peers cannot change the client IP or scheme. Operators must supply the real
container ingress address in `reverse_proxy.known_proxies`, rather than trusting every source or
assuming a container bridge is loopback. Validate external HTTPS, identity/management Cookie
security, discovery/redirect URLs, and IP budgets after deployment. Public issuer/redirect
configuration remains authoritative and is never derived from an untrusted forwarded Host.

Bootstrap/Setup have no activated application snapshot and continue their previous forwarding
behavior: they do not process these headers. Terminate/install through an appropriate protected
network; business proxy trust becomes active only after setup and restart into the normal host.
No setting key or database migration is added. A binary rollback restores the previous local
middleware and the same snapshot setting; do not run both middleware implementations together.

## Hosted-login HTTP testing foundation

The optional shared `security.hosted_login_http_test_origins` JSON list can be activated only by
a normal Host whose actual environment is exactly `Testing`. Missing/empty keeps it disabled;
all changes require restart. It is stored in the existing aggregate, never in launcher settings.
An HTTP public base URL must have its exact origin listed and must independently retain the
existing non-HTTPS issuer opt-in and issuer equality. Non-Testing Hosts refuse nonempty lists
on their next startup, even if an authenticated administrator previously saved the value.

This policy foundation does not yet enable HTTP callback registration or HTTP identity/CSRF
Cookies. See [Private-network HTTP testing](../oidc/HttpTesting.md) for strict private literal-IP
syntax, isolated-network responsibilities, staged delivery and rollback. Remove the explicit
new key through shared updates with `value=null` before running an older 44-key binary; retain
the database and external keys. No schema migration or deployment default changes are needed.
