# service_installations

Shared ServiceMantle installation-state table, mapped into the SignaCore model by
`AddServiceMantleInstallation()` and keyed by service identifier. One row per service; SignaCore uses
the single service id `signacore`.

> The **runtime authority** for installation status and the one-time setup code since ServiceMantle
> issue #128 switched SignaCore off its legacy `installation_state` table (dropped by the
> `DropInstallationState` forward migration). Reads and writes flow through the ServiceMantle
> installation/setup stores (`IServiceInstallationStore`, `IServiceSetupCodeStore`) under
> SignaCore-owned locks and transactions.

## Columns

- service_id (string, max 128, primary key) — canonical service identifier (`signacore`)
- status (integer) — ServiceMantle `InstallationStatus`: `PendingSetup` (0) or `Completed` (1)
- created_at_utc (timestamp, not null)
- completed_at_utc (timestamp, nullable) — present only once `Completed`
- version (integer, not null) — optimistic concurrency token
- setup_code_generation (integer, not null, default 0) — non-sensitive setup-code issuance counter
- setup_code_digest (string, max 74, nullable) — `sha256-v1:` digest of an issued setup code; null on
  completed rows
- setup_code_issued_at_utc (timestamp, nullable)
- setup_code_expires_at_utc (timestamp, nullable)

Timestamps use the ServiceMantle mapping's provider-default storage (`timestamp with time zone` on
PostgreSQL, `TEXT` on SQLite), which is intentionally isolated to this table and differs from the
SignaCore `DateTimeOffset`/Unix-microsecond convention used elsewhere.

## Relationships and invariants

- The ServiceMantle store enforces these invariants on read: `version >= 1`, `created_at_utc` is not
  the default value, `PendingSetup` carries no `completed_at_utc`, and `Completed` requires
  `completed_at_utc >= created_at_utc`.
- Adoption backfill (fail-closed): the historical `AddServiceInstallations` migration inserted a
  single `Completed` row for `signacore` whenever the database was anything other than a brand-new
  empty install — that is, when the legacy `installation_state.status` was `Completed` or any
  business data existed. A Pending singleton with no business data, and a brand-new empty database,
  stayed empty so anonymous setup remains open for a not-yet-completed install.
- The legacy `installation_state.setup_code_hash` was not carried over: a `Completed` row holds no
  setup-code material, and the legacy hash format was not migratable.
- Startup resolution: a missing row with business data, or a backfill-adopted `Completed` row
  with no shared `service_settings` aggregate and business data, is an upgrade of a pre-change
  deployment — it takes the protected legacy import, never anonymous setup. A genuinely completed
  installation always wrote its full settings snapshot transactionally.
- Setup completion, settings changes, and the rotate command serialize on this row (`FOR UPDATE` on
  PostgreSQL); `setup_code_digest` and `setup_code_expires_at_utc` are cleared in the same
  transaction that sets `status` to `Completed`, so a consumed code cannot be replayed.
- The configuration version reported in startup diagnostics and the admin settings API is the
  shared `service_settings` aggregate version, activated once at startup. (Before the legacy
  storage was retired, it was derived from `MAX(system_settings.version)` under this row's writer
  lock.)
- Setup codes keep SignaCore's documented 24-hour validity (the shared store's maximum lifetime);
  only the `sha256-v1:` digest is stored, never the plaintext.

## Ownership

SignaCore owns this table's migrations and every save/transaction boundary, per the ServiceMantle
persistence contract. The ServiceMantle packages never generate or run migrations and never commit a
SignaCore work unit. Writers are the adoption migration (historical), the startup resolver (pending
creation and code issuance), setup completion, the legacy import, the settings API, and the
setup-code rotation command.
