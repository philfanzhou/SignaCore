# installation_state

Singleton row recording whether this database has been initialized.

## Columns

- id (integer, primary key, fixed value 1) — enforced by a check constraint
- status (`Pending` or `Completed`)
- installation_id (UUID, not null)
- setup_code_hash (string, nullable) — one-way hash of the one-time setup code
- setup_code_expires_at (timestamp, nullable)
- completed_at (timestamp, nullable)
- configuration_version (integer, not null)

## Relationships and invariants

- First-run status is never inferred from missing configuration keys. Deleting rows from
  `system_settings` in a previously initialized database must not reopen anonymous setup and allow
  account takeover, so the `Completed` marker is durable and is never reset automatically.
- A database with no row here but with existing accounts, applications, keys, or other business data
  is an upgrade of a pre-change deployment. It takes the protected legacy import path, never Setup
  Mode.
- Only the hash and expiry of the setup code are stored. The plaintext is printed once to standard
  output and never persisted or logged.
- `setup_code_hash` and `setup_code_expires_at` are cleared in the same transaction that sets
  `status` to `Completed`, so a consumed code cannot be replayed.
- Setup completion locks this row and re-checks `status` inside a serializable transaction, so only
  one concurrent request or instance can complete an installation.
- `configuration_version` increments with every activated settings snapshot and is reported in
  startup diagnostics, so all instances can be confirmed to run the same configuration.

## Ownership

SignaCore owns all writes to this table. Editing it by hand can either lock an operator out of a
working deployment or expose unauthenticated setup on one that already owns accounts.
