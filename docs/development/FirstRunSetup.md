# First-Run Setup

A deployment with no bootstrap file first runs in Bootstrap Configuration Mode. Once the database
and root key are configured, a new empty SignaCore database runs the separate first-run Setup Mode
until an operator initializes application settings and the administrator.

## Startup state machine

Startup has a bootstrap phase and an application phase.

When the fixed bootstrap file is absent, the process remains live without composing any database,
identity, JWT, key-management, or provider services. It serves `/bootstrap`, reports readiness false,
and gates normal APIs with `503 service.phase.unavailable`. A random, rate-limited one-time bootstrap
credential is printed once to standard output and is required to test or save a database target.
Every restart issues a new credential and invalidates the previous one.

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

While installation is `Pending`, the process serves a minimal host composed of the shared
ServiceMantle capabilities: the management pipeline with its phase gate, the anonymous setup entry,
the health endpoints, and the admin SPA. While installation is `Pending`:

- `/setup` (and any console route such as `/admin`) serves the same SPA build; the SPA probes the
  setup entry itself and renders the setup form;
- `GET /management/v1/setup` reports `{"status":"pending"}`;
- `POST /management/v1/setup` accepts the completion submission;
- `/health/live` reports liveness; `/health/ready` and `/health` report not ready;
- token, discovery, JWKS, profile, gateway, and normal admin APIs have no endpoint: a read is a
  plain `404`, and a write — which routing answers with its synthetic method-mismatch endpoint —
  is answered by the shared phase gate with the fixed `503 service.phase.unavailable`, exactly as
  the Bootstrap Configuration Mode host behaves;
- the normal admin login route is unavailable.

API requests receive no identity surface at all; only browser navigation reaches the console
build, which then renders the setup form client-side. There is no server-side redirect into
`/setup` anymore.

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

Verification is rate-limited by the shared setup policy (5 requests per minute per source address)
and compares hashes in constant time. The hash and expiry are cleared in the same transaction that
completes installation.

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
`system_settings`, `service_settings`, `service_installations`, logs, audit payloads, or the
bootstrap file.

## Completion is atomic

`POST /management/v1/setup` performs the completion in one serializable transaction. The request
carries the fixed cross-site request header `X-ServiceMantle-Request: 1` and a JSON body of exactly
`{"code":"...","input":{...}}`, where `input` holds exactly the five form values: `publicBaseUrl`
(string), `allowNonHttpsIssuer` (bool), `jwtAudience` (string), `username` (string), and `password`
(string). The password confirmation is compared only in the browser and never travels. A missing,
extra, or wrongly typed field, or an HTTP shape the shared entry refuses, is answered with the fixed
management `400` before the executor runs.

The executor owns one transaction and attempts it exactly once — never under a retrying execution
strategy — in this order:

1. lock the singleton installation row (`SELECT ... FOR UPDATE` on PostgreSQL; the SQLite write
   transaction serializes on the file); a missing row is a fixed `503`, a `Completed` row is the
   fixed management `409`;
2. validate the setup code read-only; an invalid, expired, or already-rotated code is answered
   `401 {"errorCode":"management.setup.credential_invalid"}` without consuming anything, and
   before any content of the input can influence the answer;
3. read and validate the input: the five-field shape, the absolute HTTPS public base URL (HTTP only
   with the explicit opt-in), the non-empty audience, the username length, the password policy, and
   the complete proposed settings snapshot; every failure is the fixed `400`;
4. write the complete default settings snapshot into the shared `service_settings` aggregate as its
   first version (expected version 0) through the shared transactional update service — validation,
   sensitive re-protection, and the per-key `configuration.changed` shared audit rows happen inside
   this transaction; any refusal is answered with the fixed `503`. The aggregate is written before
   anything else stages, because the shared update transaction refuses a context that already
   carries pending changes;
5. run the shared ServiceMantle setup orchestration over the initial-administrator contributor:
   its read-only validation re-checks the password policy and the normalized-username uniqueness,
   and its registration stages the administrator account and the password hash without saving. A
   taken username or a policy-failing password is the fixed `400`; any other orchestration failure
   is the fixed `503`;
6. stage the setup-completed audit event — expressed with the shared audit model
   (`installation.completed` on the `service:signacore` target, operator source `setup_code`
   carrying the created account id) and projected onto the existing `audit_logs` row, where the
   actor links to the account created in step 5;
7. re-verify and stage consumption of the code together with the `Completed` status, the
   completion timestamp, and the version increment; a refusal here rolls everything staged above
   back: an installation that completed concurrently answers the fixed `409`, any other refusal the
   shared `401`;
8. save once, commit once, and only then answer `204` with an empty body.

The staging order is pinned by the shared orchestrator: it refuses to run on a context that already
carries pending changes, so the code consumption cannot silently move ahead of the contributor's
staging. The orchestrator, its contributor, and the audit projection are created fresh for every
completion request inside the request's own scope.

Only one concurrent request can succeed. A loser that arrives after the winner committed answers
the fixed conflict; a loser that was waiting on the row lock when the winner committed is released
with a serialization failure and answers the fixed `503` — its next submission observes the
completion and answers the conflict. Either way nothing of the loser's is written, and every
instance that observes completion leaves Setup Mode.

### Failure and cancellation boundaries

- A malformed request shape is refused before any transaction is opened.
- A wrong or expired code is answered from the read-only validation and never consumed; if the
  final consumption re-check refuses (for example the code expired after validation), everything
  staged in between is discarded by the rollback and nothing is committed.
- A username whose normalized form already owns a credential is refused with the fixed `400`; the
  existing rows and the code are untouched, and a unique-constraint violation is never surfaced to
  the caller.
- Any other failure — hashing, settings protection, the audit projection, the single save, the
  commit, or a transient connection problem — rolls the transaction back and answers the fixed
  `503 {"errorCode":"management.setup.unavailable"}`. The installation stays `Pending` and its code
  is preserved; the caller simply submits again. There is exactly one attempt: the completion
  transaction never runs under the provider's retrying execution strategy, so a transient failure
  can never replay a partially staged attempt.
- Caller cancellation is answered with the caller's own cancellation, never with a result. It is
  observed only once the transaction and its cleanup have settled: cancellation before the commit
  rolls everything back; cancellation after the commit keeps every committed fact, and the
  installation is `Completed` for later requests even though the caller receives no success
  response. An internal cancellation that is not the caller's is treated as an ordinary failure.

### The installation audit projection

The setup-completed event is the only audit write of the transaction on the existing `audit_logs`
table, and its projection is closed: the legacy action stays `installation.setup.completed` with
target `Installation` / `signacore`, the actor id is the account this transaction created, and the
actor name is the validated administrator username — product identity data the existing row keeps.
(The aggregate write in step 4 records its own per-key `configuration.changed` rows in the shared
`service_audit_logs` table; they carry keys and metadata only, never values.) The description
is the fixed completion note with the numeric configuration version and no longer includes the
public base URL; earlier rows keep whatever they recorded and are not rewritten. Before/after
snapshots, metadata, and correlation identifiers remain empty, and no password, setup code, root
key, or settings value is passed into the event, the description, logs, or the response.

## Transition to the normal host

After a successful setup transaction:

1. the browser shows a "configuration saved; service is starting" page and polls `/health/ready`;
2. after the completion response finishes, the host re-reads the persisted installation state in a
   fresh scope; only a `Completed` row stops the process, so an instance that lost the completion
   race also restarts, and a response lost in transit never strands a completed installation in
   Setup Mode;
3. Docker's `unless-stopped` policy, systemd, Kubernetes, or another supervisor restarts the process;
4. a manually launched process prints an instruction to start SignaCore again;
5. on restart the host observes `Completed`, loads and validates the settings, and starts normally.

A restart is used rather than rebuilding JWT, CORS, LDAP, SMS, telemetry, and key-management
singletons inside an already running dependency-injection container.

After installation is completed, `/setup` redirects browser navigation to the admin console,
`GET /management/v1/setup` answers `{"status":"completed"}`, and `POST /management/v1/setup`
answers the fixed management `409` without parsing the request body. They never permit
reinitialization.

## Upgrading an existing deployment

An upgrade must not expose first-run setup against an existing identity database.

1. Create the bootstrap file with the currently deployed database connection and root secret. Use the
   same value the deployment previously supplied as `RSA_MASTER_KEY`; the derivation is unchanged, so
   stored signing keys remain decryptable.
2. Start SignaCore. Migrations bring the schema up to date; the business data means no installation
   row is left unadopted.
3. Because meaningful business data exists without an imported configuration snapshot, SignaCore
   enters the protected legacy import path rather than Setup Mode.
4. The current effective legacy configuration is read from appsettings and environment variables —
   including the JSON section and scalar shapes the old deployment used and the pre-change key
   `AdminBootstrap:Username`, imported as `Admin:Username` — and written in one transaction straight
   into the shared `service_settings` aggregate as its first version, with secrets re-protected by
   the shared protector. The legacy `system_settings` table is never written.
5. Installation is marked `Completed` only after the imported snapshot is valid. If the import is
   incomplete or invalid, startup fails closed with key names and classification codes only,
   creates no administrator, and does not expose `/setup`. A restart after a committed import is an
   idempotent re-run: the existing aggregate is re-read and no second import is written.

Keep the legacy environment variables in place for that one start, then remove them: afterwards the
database is authoritative and remaining overrides are reported as warnings.
