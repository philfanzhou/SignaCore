# otps

Application-scoped SMS one-time-password state and rate limiting.

## Columns

- id (UUID, primary key)
- app_registration_id
- phone
- code_mac (never plaintext)
- status / expires_at / attempts / lockout_until
- hour_window_started_at / hour_send_count
- day_window_started_at / day_send_count
- provider / profile_key / provider_message_id / sent_at
- created_at / version (optimistic concurrency)

## Relationships and invariants

- app_registration_id references app_registrations.
- The schema enforces one current OTP state per application and phone according to provider migrations.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
