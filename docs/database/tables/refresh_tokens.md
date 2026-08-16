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
- source_app_id (nullable)

## Relationships and invariants

- account_id references accounts.
- app_id logically references app_registrations.app_id.
- Optional bindings preserve the source LDAP, SMS, or WeChat identity during rotation, so a
  revoked application admission also stops the refresh grant.
- source_app_id is null for a token issued by authentication and set to the originating AppId for a
  token minted by a cross-application exchange. A token with it set cannot be exchanged again, which
  is what keeps [exchange trust](./app_exchange_trusts.md) from composing across hops. See
  [ADR 0003](../../adr/0003-cross-application-refresh-grant.md).
- A cross-application exchange mints rather than rotates: the presented token belongs to the source
  application's session and is left untouched, so the two sessions are independent from that point on.
- On upgrade, startup rewrites legacy plaintext values to the versioned digest in place. Existing
  clients can continue presenting the same token because lookup hashes the presented value.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
