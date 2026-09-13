# installation_state (removed)

`installation_state` was SignaCore's legacy singleton installation-state table. It was replaced by
the shared ServiceMantle `service_installations` table and is **dropped by the
`DropInstallationState` forward migration** (ServiceMantle issue #128).

Historical notes, kept for operators reading older databases:

- The table held one row (`id = 1`) with `status` (`Pending`/`Completed`), `installation_id`,
  `setup_code_hash`, `setup_code_expires_at`, `completed_at`, and `configuration_version`.
- The `AddServiceInstallations` migration (ServiceMantle issue #70) ran a fail-closed adoption
  backfill into `service_installations` before the table was dropped: any database with a completed
  row or business data adopted a `Completed` installation row, so an upgraded database is never
  classified as `PendingSetup` and never re-exposes anonymous setup.
- Legacy pending setup-code hashes were deliberately not migrated; a not-yet-completed install gets
  a fresh setup code on its first start after the switch (the same semantics as
  `--rotate-setup-code`).

The runtime authority, its invariants, and its ownership rules are documented in
[service_installations](./service_installations.md).
