# accounts

Canonical user account state.

## Columns

- id (UUID, primary key)
- is_active
- created_at (UTC timestamp)
- remark / remark_normalized
- nickname / nickname_normalized
- last_login_at / last_login_ip / last_login_method
- total_login_count

## Relationships and invariants

- Referenced by password_credentials, user_logins, ldap_credentials, refresh_tokens, and login history.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
