# app_wechat_accesses

Per-application admission for one WeChat login identity.

## Columns

- id (UUID, primary key)
- app_registration_id
- user_login_id
- approval_source (`SelfBind`, `AutoProvision`, `ExchangeGranted`)
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
- `ExchangeGranted` records an admission derived by a
  [cross-application refresh grant](./app_exchange_trusts.md) from one the account already held at
  another application. No WeChat authorization was performed for this application, and the distinct
  value is what keeps that visible when reviewing admissions by source.
- A revoked admission is administrator state: neither logging in again nor re-binding clears it.
  Restoring requires POST /api/admin/apps/{appId}/wechat-users/{loginId}/restore.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
