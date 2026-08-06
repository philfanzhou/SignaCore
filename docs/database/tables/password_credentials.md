# password_credentials

Local username/password bindings.

## Columns

- id (UUID, primary key)
- account_id
- username / username_normalized
- password_hash
- created_at

## Relationships and invariants

- account_id references accounts.
- Normalized usernames are unique and hashes are never returned through APIs.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
