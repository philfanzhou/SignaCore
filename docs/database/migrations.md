# Migrations

## Assemblies

| Provider | Migration project |
| --- | --- |
| PostgreSQL | `src/SignaCore.Database/SignaCore.Database.csproj` |
| SQLite | `src/SignaCore.Database.Migrations.Sqlite/SignaCore.Database.Migrations.Sqlite.csproj` |

The reference BFF sample owns an independent pair of migration projects for its own database —
PostgreSQL in `samples/SignaCore.ReferenceBff.Database`, SQLite in
`samples/SignaCore.ReferenceBff.Database.Migrations.Sqlite`. They share no lineage with the
identity schema above, are never applied by the product host, and are not wired into the running
sample yet; their contracts run in the BFF's own test assembly.

## History

The migration series creates the identity schema, adds login/audit records, normalizes identity values, enforces one OTP state per scope, binds refresh tokens to applications, enables application-scoped LDAP/SMS access, adds OTP optimistic concurrency, enables application-scoped WeChat access, adds the per-application access-token audience mode, adds `system_settings` and `installation_state` so the business database becomes the configuration authority, adds `app_exchange_trusts` plus `refresh_tokens.source_app_id` for cross-application refresh grants, adds the shared ServiceMantle `service_installations` table with a fail-closed adoption backfill (ServiceMantle issue #70), drops `installation_state` now that `service_installations` is the runtime installation authority (ServiceMantle issue #128), adds the shared `service_data_protection_keys` ring, drops the legacy `data_protection_keys` table now that the shared ring is the only key store (ServiceMantle issue #491), and finally adds `authorization_requests` for the shared OIDC login continuation state (SignaCore issue #66), `identity_sessions` for the shared server-side identity session authority (SignaCore issue #95), `authorization_codes` for the shared short-lived authorization codes with their atomic one-time consumption (SignaCore issue #50), and the refresh-token family columns — `family_id`/`parent_id`/`identity_session_id`/`scope`/`auth_time`/`consumed_at` with their checks, restrictive references, and the singleton-root backfill — plus the deferred `authorization_codes.refresh_family_id` reference (SignaCore issue #97), and `logout_requests` for the prepared-logout continuation state with its digest handle, five-minute lifecycle, and restrictive client reference (SignaCore issue #68). Finally, `RetireSystemSettings` drops the legacy `system_settings` table under an in-transaction guard — on PostgreSQL a `DO`/`RAISE EXCEPTION` block, on SQLite a temp-table `CHECK` constraint — that refuses the drop while unmigrated legacy rows remain and the shared `service_settings` aggregate does not exist; its `Down` deliberately throws instead of recreating an empty table (ServiceMantle issue #556, see [System settings retirement](./system-settings-retirement.md)). The PostgreSQL-only `AlignPostgreSqlLegacyTextColumns` migration afterwards aligns the model's column types with the physical schema of the 37 `text` columns the early migrations created — it changes no physical schema and no stored value, and its `Down` is deliberately empty (SignaCore issue #269). Applied history is immutable: earlier migration files are never edited or deleted.

## Creating a migration

Select the appropriate startup factory and migration project, generate the migration with `dotnet ef`, review all generated SQL semantics, and repeat for every supported provider. Never copy a provider-specific migration blindly between projects.

The repository sets `UseArtifactsOutput`, so `dotnet ef` cannot find its own MSBuild targets under the
default path and fails with `The target "GetEFProjectMetadata" does not exist in the project`. Point it
at the artifacts intermediate directory instead, and use a tool version that matches the EF Core
packages in `Directory.Packages.props`:

```bash
dotnet ef migrations add <Name> \
  --project src/SignaCore.Database/SignaCore.Database.csproj \
  --msbuildprojectextensionspath artifacts/obj/SignaCore.Database
dotnet ef migrations add <Name> \
  --project src/SignaCore.Database.Migrations.Sqlite/SignaCore.Database.Migrations.Sqlite.csproj \
  --msbuildprojectextensionspath artifacts/obj/SignaCore.Database.Migrations.Sqlite
```

## Deployment

The host provisions the database where supported and applies the selected provider's migrations at startup. Production deployments should back up data, use a database principal with the required migration permissions, serialize schema upgrades, and verify the EF migrations history after rollout. Upgrades that cross the `RetireSystemSettings` migration must follow the staged bridge procedure in [System settings retirement](./system-settings-retirement.md).

## Startup migration gate

At startup, `InstallationStartup` runs the shared ServiceMantle migration orchestration (`DatabaseMigrationOrchestrator`) through an internal executor before any installation-state resolution, legacy configuration import, or snapshot loading happens. The orchestration applies a limited, read-only observation to the target and only allows migration to proceed from an `Empty` or `PendingMigration` state:

| Observed history and objects | Outcome |
| --- | --- |
| SQLite file missing, or target schema has no application objects and no history | `Empty` — full migration runs |
| Applied history is a strict prefix of the current lineage | `PendingMigration` — full migration runs |
| Applied history equals the current lineage | Executor skipped; startup continues |
| Any applied migration id unknown to this build | `version_too_new` — startup fails closed |
| Known history with gaps, or an empty history beside existing application tables/views | `inspection_failed` — startup fails closed; unknown databases are never adopted |
| Post-execution re-inspection not at the current version | `final_state_invalid` — startup fails closed |

The observation only reads the migration schema the connection actually uses (its history table plus that schema's object catalog); the history table and EF's own lock table are not application objects, and any other table or view counts even when empty. Read-only observation never creates the SQLite file, the history table, or any data.

The executor's `ExecuteAsync` owns the full SignaCore migration workflow (formerly `SchemaMigrator`), so the PostgreSQL expand/backfill/contract phases, normalized-value collision checks, and OTP uniqueness checks are unchanged.

Locking:

- PostgreSQL keeps SignaCore's original outer advisory lock, which still serializes the whole startup phase (migration, installation resolution, legacy import, snapshot loading). Inside it, the shared migration lock is acquired through the real `PostgreSqlMigrationLockProvider` under the fixed service id `signacore`, with a fixed 30-second wait budget that covers only that lock — not the rest of startup. The lock order is fixed: outer lock → shared migration lock → shared release → installation resolution/import → outer release. The two locks use different keys; the old lock is never re-acquired.
- SQLite is declared a single-process local-file deployment. The shared single-instance overload serializes migrations per canonical local file target within the process. SignaCore does not claim cross-process or multi-host migration coordination for SQLite.
- Failures of the gate surface as a fixed error code and fixed message (for example `SignaCore startup database migration failed (migration.inspection_failed).`) before any setup code is issued; original exceptions, inner exceptions, and connection secrets never reach this diagnostic. Caller cancellation is honored throughout and takes precedence over success or failure.

## Rename note

Existing migration IDs and table names are unchanged. The new assemblies contain the same migration lineage under the `SignaCore` namespace, so an existing database remains compatible when the connection string is retained.
