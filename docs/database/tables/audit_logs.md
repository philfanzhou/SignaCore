# audit_logs

Administrative and security-relevant change records.

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

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
