# Deployment

## Build

```bash
IMAGE_TAG=latest ./build.sh
```

This produces `signacore:latest` from `src/SignaCore.Host/Dockerfile`. The image builds the Vue admin application, restores and publishes `SignaCore.Host`, runs as the non-root `app` user, exposes port 5002, and starts `SignaCore.Host.dll`.

## Releasing

Releases are driven entirely by pushing a tag. Nothing is published by hand.

```bash
git tag -a 0.1.4 -m "SignaCore 0.1.4"
git push origin 0.1.4
```

The tag must be numeric `MAJOR.MINOR.PATCH`; CI rejects anything else. Pushing it runs the full
pipeline — build, unit tests, integration and HTTP contract tests, the image vulnerability scan, the
containerised first-run and smoke assertions, and the database contract matrix — and only if all of
it passes does the release happen, in two steps:

1. **Publish GHCR Image** builds and pushes `ghcr.io/philfanzhou/signacore`, tagged with the exact
   version, the `MAJOR.MINOR` line, and `latest`, with provenance and an SBOM attached.
2. **Publish GitHub Release** creates the release for the tag, quoting the digest that was actually
   published and appending GitHub's generated changelog.

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

On the first start, leave the directory empty. SignaCore stays live, prints a one-time bootstrap code
to standard output, and serves `/bootstrap`. The protected form tests the database and creates this
exact file atomically, generating the master key for a new installation:

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

- Terminate TLS at the service or a trusted reverse proxy.
- Prepare the writable persistent bootstrap directory, complete protected bootstrap configuration,
  restrict the resulting file to mode `0600`, and back it up.
- Set `ReverseProxy:KnownProxies` when TLS terminates at a non-loopback proxy so forwarded scheme and
  client IP are accepted only from that proxy.
- Use a production database and verify the selected provider's migrations.
- Complete first-run setup and record the administrator credentials in your secret manager.
- Set the JWT audience expected by downstream services; the issuer follows the public base URL.
- Publish `/.well-known/openid-configuration` and JWKS through the public base URL.
- Point orchestrator and Consul health checks at `/health/ready`.
- Scrape `/metrics` and connect logs/traces to the chosen observability backend.
- Remove legacy application-setting environment variables from the launcher; startup logs any that
  remain.
- Run the verification steps after deployment.

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
3. Leave the existing legacy environment variables in place for one start. Migrations add
   `system_settings` and `installation_state`, and because business data already exists SignaCore runs
   the protected legacy import instead of exposing `/setup`.
4. Confirm startup reported a completed import, then remove the legacy variables from the launcher and
   redeploy. Anything still supplied is logged as an ignored legacy override.
5. Change settings from then on through the administration pages, followed by a coordinated rolling
   restart.
