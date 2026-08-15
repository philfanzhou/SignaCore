# ADR 0002: Database-backed Configuration and First-Run Setup

- Status: Accepted
- Date: 2026-08-15

## Context

Global application configuration used to arrive from appsettings, environment variables injected by
the launcher, and Consul KV with a local plaintext cache. That had three consequences worth naming:

- instances could disagree. Precedence differed per host, and the Consul cache meant one instance
  could serve yesterday's configuration after a Consul outage;
- the deployment had to hand plaintext secrets to the process environment — the administrator
  password, the SMS OTP HMAC key, the RSA master key — so every launcher script became a secret
  store;
- configuration changes had no transaction, no audit trail, and no version.

Two candidate homes were considered and rejected: a local SQLite configuration database, which
reintroduces per-instance drift and file locking on shared storage, and a separate central
configuration service, which adds a second system to operate and back up.

## Decision

Store global application configuration in the existing business database, in `system_settings`.
Record installation completion in a singleton `installation_state` row.

Keep exactly two things outside it, because they are required to open and decrypt that database:

1. the database provider, server version, and connection string;
2. the external root key.

Both live in one writable, persistent bootstrap file at a fixed path,
`<application-base>/config/signacore.bootstrap.json`, so no additional environment variable is needed
to deploy. The root key is inline; no second key file is part of the contract. When the file is
absent, a minimal host serves a one-time-code-protected bootstrap UI and writes the file atomically.

Split startup into a bootstrap phase (open the database, migrate, determine installation state) and
an application phase (compose services against a validated settings snapshot). A new, empty database
runs a minimal Setup Mode host gated by a one-time setup code printed once to standard output.

## Consequences

- Every instance reads the same active configuration; there is no per-instance drift and no local
  configuration cache to go stale.
- Configuration changes use the same transactions, migrations, audit infrastructure, backup policy,
  and availability guarantees as the identity data that depends on them.
- Database unavailability becomes a fatal startup error. This is deliberate: an instance cannot
  provide correct identity behavior while its authoritative identity database is unreachable.
- Backup and recovery now couple three artifacts — the database, the root key, and the bootstrap file
  that names the database. Restoring one without the others fails closed rather than silently
  rotating signing keys.
- Consul KV stops being a configuration authority. Optional service discovery remains, with its own
  settings read from `system_settings`.
- A deployment that selects SQLite as the business database remains single-instance and must not be
  advertised as supporting active multi-instance operation.
- Activating a change currently requires a restart, because subsystems have no reload support yet.
  Multiple instances need a coordinated rolling restart.
- Upgrading an existing deployment needs a one-time legacy import path, and that path must never be
  confusable with first-run setup — a database that already owns accounts must never expose
  unauthenticated setup.

## Alternatives considered

- **Local SQLite configuration database.** Rejected: per-instance drift, plus file locking on shared
  or network storage.
- **Separate central configuration database or service.** Rejected: a second system to operate, back
  up, and keep available, for data that is already coupled to the identity database.
- **Keeping Consul KV as the authority.** Rejected: the fallback chain is what allowed instances to
  disagree, and the local cache stored configuration in plaintext on disk.
- **Hot-reloading every subsystem after a settings change.** Rejected for the first implementation:
  partially rebuilding JWT, CORS, LDAP, SMS, telemetry, and key-management singletons inside a live
  container is more failure-prone than a controlled restart, and these are security-sensitive
  settings.
