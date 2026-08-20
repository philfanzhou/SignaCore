# app_sms_accesses

Per-application admission for one SMS login identity.

## Columns

- id (UUID, primary key)
- app_registration_id
- user_login_id
- approval_source (`Admin`, `AutoProvision`, `ExchangeGranted`)
- is_active
- approved_by
- created_at

## Relationships and invariants

- app_registration_id references app_registrations and cascades on delete.
- user_login_id references user_logins and cascades on delete.
- (app_registration_id, user_login_id) is unique.
- A disabled admission remains explicit administrator state; OTP verification does not silently reactivate it.
- `ExchangeGranted` records admission derived by a cross-application refresh grant without a new OTP verification.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
