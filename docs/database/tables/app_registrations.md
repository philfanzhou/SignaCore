# app_registrations

Registered client applications and their authentication policies.

## Columns

- id (UUID, primary key)
- app_id / app_id_normalized (unique identity)
- app_secret_hash
- app_name
- callback_url / callback_expires_at
- is_active / created_at
- ldap_login_mode
- sms_login_mode / sms_profile_key
- wechat_login_mode
- audience_mode
- client_type
- allow_authorization_code
- allowed_scopes
- allow_refresh_token
- identity_session_max_age_seconds (nullable)

## Relationships and invariants

- Referenced by application-scoped LDAP/SMS/WeChat access and OTP records.
- Refresh tokens store app_id as a logical binding.
- audience_mode selects the aud claim of access tokens: the shared Jwt:Audience, or this app_id.
- Interactive OIDC is fail closed by default: `Confidential`, authorization code and interactive
  refresh disabled, `openid` as the only allowed scope, and no application session maximum age.
- `allowed_scopes` is a canonical space-delimited closed set ordered as `openid`, `profile`, then
  `offline_access`.
- Code flow may be enabled only for a confidential application with `PerApplication` audience mode
  and at least one row of kind `Redirect` in [app_redirect_uris](./app_redirect_uris.md).
- `identity_session_max_age_seconds`, when present, is between 1 and 43,200 seconds.
- `callback_url` is a server-to-server claims callback. It is never copied to, derived from, or
  validated as an interactive redirect URI.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
