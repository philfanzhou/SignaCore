# First-Run Setup

A deployment with no bootstrap file first runs in Bootstrap Configuration Mode. Once the database
and root key are configured, a new empty SignaCore database runs the separate first-run Setup Mode
until an operator initializes application settings and the administrator.

## Startup state machine

Startup has a bootstrap phase and an application phase.

When the fixed bootstrap file is absent, the process remains live without composing any database,
identity, JWT, key-management, or provider services. It serves `/bootstrap`, reports readiness false,
and gates normal APIs with `503 bootstrap_configuration_required`. A random, rate-limited one-time
bootstrap code is printed once to standard output and is required to test or save a database target.

For a new installation, the bootstrap backend generates the master key; for migration or recovery,
the operator submits the existing key as a write-only value. The backend validates the provider and
connection, opens and classifies the database, verifies the key against protected data when present,
then flushes a temporary file and atomically replaces `config/signacore.bootstrap.json` with mode
`0600`. It stops the minimal host only after the response finishes so a supervisor can restart it.

When the file is present, the bootstrap phase strictly parses it, resolves the inline root key
without logging it, validates the database provider/version/connection, connects to the business
database, acquires the provider-appropriate migration lock, applies all schema migrations, and then
determines the installation state:

| Observed state | Outcome |
| --- | --- |
| Empty new database, no state row | Create a `Pending` installation and a one-time setup code; run Setup Mode |
| `Pending` | Run Setup Mode |
| `Completed` | Load and validate the active settings snapshot, then run the normal host |
| No state row, but accounts / applications / keys / other business data exist | Protected legacy import; never anonymous setup |
| `Completed` with missing or invalid required settings | Fail closed with actionable diagnostics; never revert to `Pending` |

Database unavailability is a fatal startup error. There is no local persisted fallback: an instance
cannot provide correct identity behavior while its authoritative identity database is unreachable.

## Setup Mode

While installation is `Pending`:

- `/admin` and any other browser navigation redirect to `/setup`;
- `/setup` serves the setup UI;
- `/api/setup/status` and `/api/setup/complete` are available;
- `/health/live` reports process and database liveness;
- `/health/ready` reports not ready;
- token, discovery, JWKS, profile, gateway, and normal admin APIs return a structured
  `503 installation_required` JSON response;
- the normal admin login route is unavailable.

API requests receive JSON rather than an HTML redirect; only browser navigation is redirected.

## The one-time setup code

An unprotected "first visitor becomes administrator" flow is forbidden — the setup page of an
identity service is reachable by anyone who can reach the service at all.

When a new `Pending` installation is created under the database initialization lock, SignaCore
generates a cryptographically random setup code, stores only a one-way hash and an expiry, and prints
the plaintext once to standard output:

```
docker logs signacore
```

```
==============================================================
 SignaCore first-run setup
--------------------------------------------------------------
 This database has not been initialized yet.
 Open /setup in a browser and enter the one-time setup code:

     ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2-34567

 The code expires at 2026-08-16 05:41:55 UTC.
 It is shown only once. To issue a new one, run:
     dotnet SignaCore.Host.dll --rotate-setup-code
==============================================================
```

Verification is rate-limited to 5 attempts per minute per source address and compares hashes in constant
time. The hash and expiry are cleared in the same transaction that completes installation.

The code is an ephemeral proof that the user can inspect the deployment, not an application setting;
it does not belong in the bootstrap file.

### Rotating a lost or expired code

```bash
docker exec signacore dotnet SignaCore.Host.dll --rotate-setup-code
```

The command is allowed only while the installation is `Pending`, requires access to the bootstrap
secret, uses the database lock, and prints the new code once. It cannot reset a `Completed`
installation.

## The setup form

First-run setup collects only what is needed to establish an operable secured installation:

- canonical public base URL;
- explicit insecure HTTP issuer opt-in, default off;
- initial JWT audience, default `SignaCore.Services`;
- initial administrator username;
- initial administrator password and confirmation;
- one-time setup code.

The public base URL must be absolute HTTPS unless the operator explicitly enables the insecure HTTP
option. The rule does not inspect IP ranges, host names, or network topology. `Jwt:Issuer` is
initialized to the normalized public base URL and is not presented as a duplicate field. Safe
defaults are inserted for access-token lifetime, refresh-token lifetime, password hashing, callback
policy, and disabled optional providers.

SMS, WeChat, LDAP, Loki, OpenTelemetry, callback allowlists, and application registrations are not
part of first-run setup. They are configured from authenticated administration pages later.

The administrator plaintext password is used only to create its password hash. It is never stored in
`system_settings`, `installation_state`, logs, audit payloads, or the bootstrap file.

## Completion is atomic

`POST /api/setup/complete` performs the following in one serializable transaction:

1. re-read and lock the singleton installation row;
2. confirm the status is still `Pending` and validate the setup code;
3. validate the public base URL and administrator password policy;
4. insert the complete default global-settings snapshot;
5. create the initial administrator and password hash;
6. write a setup-completed audit event without sensitive values;
7. change the status to `Completed`, increment the configuration version, and invalidate the setup
   code;
8. commit.

Only one concurrent request can succeed. Others receive a completed/conflict result without changing
data, and every instance that observes completion leaves Setup Mode.

## Transition to the normal host

After a successful setup transaction:

1. the browser shows a "configuration saved; service is starting" page and polls `/health/ready`;
2. the host calls `StopApplication()` after the response has completed;
3. Docker's `unless-stopped` policy, systemd, Kubernetes, or another supervisor restarts the process;
4. a manually launched process prints an instruction to start SignaCore again;
5. on restart the host observes `Completed`, loads and validates the settings, and starts normally.

A restart is used rather than rebuilding JWT, CORS, LDAP, SMS, telemetry, and key-management
singletons inside an already running dependency-injection container.

After installation is completed, `/setup` redirects browser navigation to the admin console and
`/api/setup/complete` answers `409`. They never permit reinitialization.

## Upgrading an existing deployment

An upgrade must not expose first-run setup against an existing identity database.

1. Create the bootstrap file with the currently deployed database connection and root secret. Use the
   same value the deployment previously supplied as `RSA_MASTER_KEY`; the derivation is unchanged, so
   stored signing keys remain decryptable.
2. Start SignaCore. Migrations add `system_settings` and `installation_state`.
3. Because meaningful business data exists and no installation state does, SignaCore enters the
   protected legacy import path rather than Setup Mode.
4. The current effective legacy configuration is read from appsettings and environment variables,
   validated, and stored transactionally, with secrets encrypted. The pre-change key
   `AdminBootstrap:Username` is imported as `Admin:Username`.
5. Installation is marked `Completed` only after the imported snapshot is valid. If the import is
   incomplete or invalid, startup fails closed with the list of missing keys, creates no
   administrator, and does not expose `/setup`.

Keep the legacy environment variables in place for that one start, then remove them: afterwards the
database is authoritative and remaining overrides are reported as warnings.
