# Editable Bootstrap Configuration Plan

- Status: Implemented
- Date: 2026-08-15
- Scope: SignaCore bootstrap configuration, setup UI, startup state machine, and deployment contract

## 1. Objective

Simplify SignaCore deployment so an operator does not have to prepare many environment variables,
Consul keys, or a separate master-key file before the service can start.

SignaCore must be able to start a protected bootstrap configuration UI when its bootstrap file does
not exist. That UI creates and later updates one writable, persistent configuration file containing
only:

1. the business-database connection information; and
2. the external master key itself.

All other application settings remain authoritative in the shared business database and are managed
through first-run setup or authenticated administration pages.

SignaCore remains network-location agnostic. It may run on the public Internet, a private network, a
single-host Docker network, or another reachable topology. Application code must not infer or
restrict the deployment zone from an IP address or host name.

## 2. Decisions

### 2.1 Canonical bootstrap file

The canonical path remains:

```text
<application-base>/config/signacore.bootstrap.json
```

In the container it is:

```text
/app/config/signacore.bootstrap.json
```

The target schema is deliberately limited to these fields:

```json
{
  "Database": {
    "Provider": "PostgreSQL",
    "ServerVersion": "15",
    "ConnectionString": "Host=database;Port=5432;Database=signacore;Username=signacore;Password=replace-me"
  },
  "MasterKey": "a-cryptographically-random-external-root-key"
}
```

Field contract:

| Field | Required | Purpose |
| --- | --- | --- |
| `Database.Provider` | Yes | Selects the supported business-database provider and migration set. |
| `Database.ServerVersion` | Yes | Supplies the provider server version required by provider-specific behavior. |
| `Database.ConnectionString` | Yes | Opens the shared business database that owns identity data and global settings. |
| `MasterKey` | Yes | External root key used to decrypt stored signing private keys and secret system settings. |

No other application setting belongs in this file.

### 2.2 Inline master key only

The target user-facing contract does not use a separate `MasterKeyFile` or a second key file. The
master key is stored inline in `signacore.bootstrap.json`.

The entire bootstrap file is therefore a secret. It must:

- live on persistent storage outside the container's writable layer;
- be readable and writable only by the SignaCore runtime identity;
- use mode `0600` on Unix-like hosts;
- never be committed to source control;
- never be printed to logs or returned by an API;
- be backed up together with the business database.

The master key is not the JWT signing private key. It is the external root of trust that protects the
RSA signing private keys and encrypted database-backed settings. Losing it makes those values
undecryptable. Replacing it without rewrapping protected data must fail closed.

### 2.3 Writable configuration mount

The configuration directory is mounted read-write, not read-only. For example:

```text
./config:/app/config
```

The setup and administration backend may create or update the bootstrap file. Writes must use:

1. strict model validation;
2. a temporary file in the same directory;
3. an explicit file flush;
4. permission enforcement;
5. an atomic replacement of the target file.

A failed or interrupted write must leave the last valid file intact.

## 3. Configuration ownership

Only the database bootstrap and external root key live in the local file.

The following settings remain in the business database (`system_settings`), not in the bootstrap
file:

- `Endpoints:PublicBaseUrl`;
- `Jwt:Issuer`;
- `Jwt:Audience`;
- the explicit HTTP issuer opt-in (`Security:AllowNonHttpsIssuer`, or its final product name);
- token and refresh-token lifetimes;
- callback security and allowlists;
- SMS, WeChat, and LDAP settings;
- reverse-proxy trust;
- observability endpoints;
- optional Consul service-discovery settings;
- application registrations and per-application policies.

Secret database-backed settings continue to be encrypted with a key derived from `MasterKey`.

Image names, container names, host ports, bind mounts, restart policy, time zone, and process logging
shape remain launcher/orchestrator concerns.

## 4. Startup state machine

### 4.1 Bootstrap file is absent

SignaCore must not terminate merely because `signacore.bootstrap.json` is absent. It starts a minimal
Bootstrap Configuration Mode that:

- serves the bootstrap configuration UI;
- exposes liveness;
- reports readiness as false;
- blocks discovery, JWKS, token, gateway, profile, and normal administration APIs with a structured
  `503 bootstrap_configuration_required` response;
- does not initialize normal identity services before a validated database and master key exist.

Because SignaCore may be reachable from a public or private network, the bootstrap UI must not use a
"first visitor wins" flow. A cryptographically random, rate-limited, one-time bootstrap code is
printed once to standard output and is required to save the bootstrap configuration. This code is
ephemeral operational proof, not another configuration-file field.

The bootstrap form collects:

- database provider;
- database server version;
- either structured database fields or an advanced full connection string;
- a new-install versus existing-install choice;
- the one-time bootstrap code.

For a new installation, the backend generates a cryptographically strong `MasterKey`; the operator
does not invent one. For migration or recovery, the UI accepts the existing master key as a
write-only value. The key is never returned to the browser after it has been stored.

Before saving, the backend validates the provider and connection string, opens the database, and
checks whether the supplied master key is compatible with any existing encrypted data. It then
writes the file atomically and requests a controlled restart.

### 4.2 Bootstrap file is present

SignaCore strictly parses the file, resolves the inline master key, connects to the business
database, applies migrations under the provider-appropriate migration lock, and determines the
installation state.

- A new empty database enters the existing first-run application setup.
- A completed installation loads and validates the authoritative settings snapshot.
- An existing legacy database enters the protected legacy import path and never exposes anonymous
  first-run application setup.
- A wrong master key, invalid file, or unreachable configured database fails closed with actionable
  diagnostics that do not disclose secrets.

### 4.3 Database is connected but application settings are absent

The first-run application setup initializes the shared database settings and administrator. It is a
separate phase from creating the bootstrap file.

At minimum the setup UI collects:

- canonical public base URL;
- whether plain HTTP is explicitly allowed, default `false`;
- initial JWT audience, with the SignaCore product default unless an operator overrides it;
- initial administrator username and password;
- the protected setup code required by the existing installation flow.

`Jwt:Issuer` defaults to the normalized public base URL and is not presented as a duplicate field.
SignaCore does not classify the URL as public, private, or Docker-only. HTTPS works without an
exception. HTTP works only after the operator explicitly enables the insecure-transport option.

## 5. Editing after installation

The authenticated configuration UI may update the bootstrap file, subject to these rules:

### 5.1 Database connection

- The current password is never returned to the browser.
- A replacement connection must be supplied as a complete write-only value.
- The target database is tested and classified before the file is changed.
- The UI clearly states whether the target is the current installation, an empty database, or a
  database containing incompatible SignaCore data.
- Saving requires an explicit confirmation and a controlled restart.

For multiple running instances, changing the database target is a coordinated deployment operation.
Updating one instance must not silently claim that the other instances were updated.

### 5.2 Master key

- Before protected data exists, setup may regenerate or replace the key.
- After protected data exists, the ordinary editor shows only "configured" and never the value.
- A blank submitted key means "keep the current key," not "erase it."
- Direct replacement is rejected after initialization.
- Future key rotation, if implemented, must rewrap every protected RSA private key and encrypted
  system setting transactionally before committing the new bootstrap file.

This restriction is a data-integrity requirement, not an additional deployment setting.

## 6. Multi-instance behavior

The business database remains the authority for all global application settings, so active instances
do not use local SQLite configuration and do not maintain per-instance setting caches.

Every instance must receive an identical bootstrap file containing the same database target and
master key. A practical deployment sequence is:

1. initialize one instance;
2. securely distribute the resulting bootstrap file to the remaining instances;
3. start or scale the remaining instances;
4. verify that all instances report the same database identity and configuration version.

The built-in UI edits the file of the instance that handled the request. Cluster-wide bootstrap-file
distribution and coordinated restart remain orchestrator responsibilities. The UI and API must state
this explicitly rather than pretending a local file write updated the cluster.

SQLite may still be selected as the SignaCore business database for a single-instance installation.
It must not be presented as supporting active multi-instance operation.

## 7. Implementation outcome

The implementation now closes the differences recorded when this plan was proposed:

- a missing file starts the minimal, protected Bootstrap Configuration Mode instead of terminating;
- a present malformed file remains a fail-closed startup error;
- the persistent configuration directory is mounted read-write and the file is replaced atomically;
- the canonical schema accepts only an inline `MasterKey`; the legacy separate-file provider was
  removed;
- bootstrap configuration and database-backed first-run application setup are separate phases;
- first-run setup exposes the explicit HTTP opt-in and initial JWT audience;
- the launcher recognizes both bootstrap-required and setup-required live/not-ready states;
- authenticated administration can test and update the local instance's database bootstrap without
  returning its connection string, password, or master key;
- wrong master keys fail closed without generating or rotating signing keys.

Automated coverage exercises missing-file hosting, structured 503 gating, code rejection and expiry,
strict schema parsing, inline-key creation, Unix permissions, first-run transaction/concurrency,
HTTP opt-in, custom audience, and wrong-key startup behavior.

## 8. Expected implementation areas

The implementing agent should inspect and update at least:

- bootstrap option models, parsing, and master-key resolution;
- host startup composition and the bootstrap/application state machine;
- setup-mode middleware and health behavior;
- setup/admin controllers and request/response models;
- Vue setup and authenticated settings UI;
- Docker mount behavior and `start.sh`;
- deployment, configuration, first-run, security, and recovery documentation;
- unit and integration coverage.

The exact file list should follow the repository's current structure rather than being hard-coded in
this plan.

## 9. Acceptance criteria

### Bootstrap creation and recovery

- With no bootstrap file, the process stays live and serves the protected bootstrap UI.
- Readiness remains false and normal identity endpoints return a structured 503.
- An invalid or expired one-time bootstrap code cannot save configuration.
- Invalid database settings do not create or replace the file.
- A successful setup creates exactly the agreed schema with inline `MasterKey`.
- No separate master-key file is required or generated.
- The stored file has restrictive permissions and survives container replacement.
- Restarting loads the file and reaches database-backed first-run setup or normal mode.

### Secret safety

- The connection string, database password, master key, signing private keys, and application secrets
  never appear in logs, health output, audit payloads, or API responses.
- The UI never retrieves an existing plaintext master key or database password.
- A wrong master key fails closed and never causes automatic signing-key rotation.
- A partial write or process interruption preserves the previous valid bootstrap file.

### Runtime configuration

- The canonical identity URL and HTTP opt-in are stored in the business database, not the bootstrap
  file.
- HTTPS is accepted without an insecure-transport override.
- HTTP is rejected until explicitly enabled, regardless of whether its address looks public,
  private, loopback, or container-local.
- The product imposes no public-versus-private deployment-zone restriction.
- Database-backed setting changes remain transactional, audited, versioned, and restart-activated.

### Multi-instance

- Two instances using identical bootstrap files and the same business database load the same active
  configuration version.
- Concurrent first-run completion remains single-winner under the database lock/transaction.
- SQLite deployments are identified as single-instance only.

## 10. Non-goals

- Storing normal application configuration in the bootstrap file.
- Reintroducing Consul KV as a configuration authority.
- Adding a local SQLite configuration database beside the business database.
- Inferring deployment security from IP ranges, DNS suffixes, or Docker host names.
- Hot-reloading security-sensitive singleton graphs in the first implementation.
- Treating raw master-key replacement as an ordinary settings edit.

## 11. Final configuration boundary

The intended ownership model is:

```text
signacore.bootstrap.json
  -> Database.Provider
  -> Database.ServerVersion
  -> Database.ConnectionString
  -> MasterKey

business database / system_settings
  -> public base URL and issuer
  -> audience and token policies
  -> explicit HTTP opt-in
  -> callback, provider, observability, discovery, and other global settings

launcher / orchestrator
  -> image, container, ports, mounts, restart policy, and bootstrap-file distribution
```

This boundary is the implementation target for subsequent verification and development work.
