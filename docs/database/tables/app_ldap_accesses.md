# app_ldap_accesses

Per-application admission for one LDAP credential.

## Columns

- id (UUID, primary key)
- app_registration_id
- ldap_credential_id
- approval_source (`Admin`, `AutoProvision`, `ExchangeGranted`)
- is_active
- approved_by
- created_at

## Relationships and invariants

- app_registration_id references app_registrations and cascades on delete.
- ldap_credential_id references ldap_credentials and cascades on delete.
- (app_registration_id, ldap_credential_id) is unique.
- A disabled admission remains explicit administrator state; authentication does not silently reactivate it.
- `ExchangeGranted` records admission derived by a cross-application refresh grant without a new directory bind.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
