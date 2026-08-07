# app_wechat_accesses

Per-application admission for one WeChat login identity.

## Columns

- id (UUID, primary key)
- app_registration_id
- user_login_id
- approval_source (`SelfBind`, `AutoProvision`)
- is_active
- created_at

## Relationships and invariants

- app_registration_id references app_registrations and cascades on delete.
- user_login_id references user_logins and cascades on delete, so unbinding WeChat removes every
  application admission derived from that binding.
- (app_registration_id, user_login_id) is unique.
- There is no administrator approval source: an OpenId is only knowable after the user authorizes,
  so admissions are created by the user (`SelfBind`) or by the first login under `AutoProvision`.
  Administrators revoke; they do not pre-grant.
- A revoked admission is only restored by an explicit rebind, never by logging in again.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
