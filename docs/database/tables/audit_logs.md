# audit_logs (legacy, retained)

`audit_logs` was SignaCore's own administrative and security-relevant change record table. New
action audits are staged by the shared ServiceMantle writer into the shared `service_audit_logs`
table inside the caller's unit of work, and the admin console reads them through the restricted
shared query (ServiceMantle issue #132).

The table itself is **retained, not dropped**: existing history rows stay as-is across upgrades
(no migration, backfill, or format conversion is performed), and nothing writes to, reads from,
or cleans the table anymore. The legacy rows are not surfaced by the restricted query. Fresh
installations still create the empty table through the historical migrations.

Historical notes, kept for operators reading older databases:

## Columns

- id (UUID, primary key)
- action
- target_type / target_id
- actor_id / actor_name
- before_snapshot / after_snapshot
- description
- client_ip / correlation_id
- created_at

## Relationships and invariants

- actor_id may refer to an account; snapshots are JSON text and must exclude secrets.

## Ownership

SignaCore owned all writes to this table while it was live. Other services must use the HTTP API
rather than direct database access.
