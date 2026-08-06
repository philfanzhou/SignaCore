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

## Relationships and invariants

- Referenced by application-scoped LDAP/SMS access and OTP records.
- Refresh tokens store app_id as a logical binding.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
