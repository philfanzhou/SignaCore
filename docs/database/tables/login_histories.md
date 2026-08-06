# login_histories

Successful and failed authentication event history.

## Columns

- id (UUID, primary key)
- account_id (nullable)
- username
- auth_method / event_type
- client_ip / user_agent
- failure_reason
- app_id / correlation_id
- created_at

## Relationships and invariants

- account_id may reference accounts; a nullable value permits recording pre-authentication failures.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
