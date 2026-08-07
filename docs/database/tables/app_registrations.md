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

## Relationships and invariants

- Referenced by application-scoped LDAP/SMS/WeChat access and OTP records.
- Refresh tokens store app_id as a logical binding.
- audience_mode selects the aud claim of access tokens: the shared Jwt:Audience, or this app_id.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
