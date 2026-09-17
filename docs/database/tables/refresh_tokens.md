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
- family_id (UUID, non-null; the family root id — every legacy row is a singleton root with
  `family_id = id`)
- parent_id (UUID, nullable; the immediate interactive parent — null on every root and every
  legacy row, with a unique index so an interactive parent has at most one child)
- identity_session_id (UUID, nullable; non-null only for interactive family members)
- scope (nullable, max 32; the canonical interactive family scope snapshot, byte-for-byte copied
  from the authorization code — null for legacy rows)
- auth_time (nullable; the original interactive session authentication time — null for legacy rows)
- consumed_at (nullable; the successful interactive rotation fact — null for live/revoked
  interactive members and always null for legacy rows, which only ever set is_revoked)

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
- `family_id`, `parent_id`, and `identity_session_id` are restrictive references (to this table,
  this table, and `identity_sessions`); nothing cascades, and deleting a referenced root, parent, or
  session fails. `authorization_codes.refresh_family_id` restrictively references the family root.
- Two check constraints make every row either a complete legacy row (`identity_session_id`,
  `scope`, `auth_time`, `consumed_at`, and `parent_id` all null) or a complete interactive row
  (`identity_session_id`, `scope`, and `auth_time` all non-null), and either a self-referencing
  parentless root or a child of another row: `CK_refresh_tokens_family_marker` and
  `CK_refresh_tokens_family_shape`.
- Legacy issuance, same-app rotation, and cross-application exchange all produce singleton roots
  (`family_id = id`, interactive markers null), and legacy rotation only ever matches rows without
  an identity session, so it can never revoke an interactive family member.
- Cleanup (`RemoveExpiredAndRevoked`) deletes only legacy rows: expired-or-revoked rows without an
  identity session. Interactive families are removed child-first by the family API, because a
  whole-family single-statement delete under `ON DELETE RESTRICT` fails on SQLite (see
  [Persistence](../../oidc/Persistence.md) "Retention and cleanup").
- Stored `token_value` bytes are preserved whatever their representation: the one-time startup
  plaintext-to-digest conversion no longer exists, and deployments older than the minimum supported
  upgrade version clear this table before upgrading (see Deployment's "Minimum supported upgrade
  version"). Lookup hashes the presented value, so digest-protected clients keep rotating.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
