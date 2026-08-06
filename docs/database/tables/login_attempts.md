# login_attempts

Password-login failure counts and lockout state by normalized username.

## Columns

- id (UUID, primary key)
- username / username_normalized
- last_attempt_at
- failed_attempts
- lockout_until

## Relationships and invariants

- The normalized username is the lookup key used by password lockout policy.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
