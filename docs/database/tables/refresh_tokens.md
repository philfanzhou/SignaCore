# refresh_tokens

Rotating, revocable refresh credentials bound to an account and application.

## Columns

- id (UUID, primary key)
- account_id
- token_value (versioned SHA-256 digest; the bearer token itself is never persisted)
- expires_at / created_at
- is_revoked
- app_id
- ldap_credential_id (nullable)
- sms_user_login_id (nullable)
- wechat_user_login_id (nullable)

## Relationships and invariants

- account_id references accounts.
- app_id logically references app_registrations.app_id.
- Optional bindings preserve the source LDAP, SMS, or WeChat identity during rotation, so a
  revoked application admission also stops the refresh grant.
- On upgrade, startup rewrites legacy plaintext values to the versioned digest in place. Existing
  clients can continue presenting the same token because lookup hashes the presented value.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
