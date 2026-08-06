# user_logins

External provider identity bindings, including phone and WeChat identities.

## Columns

- id (UUID, primary key)
- account_id
- provider_name / provider_name_normalized
- provider_user_id

## Relationships and invariants

- account_id references accounts.
- Provider name plus provider user id identifies an external login.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
