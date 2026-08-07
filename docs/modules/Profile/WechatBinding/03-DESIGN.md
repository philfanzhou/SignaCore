# WeChat Binding: Design

## Components

ProfileController, WechatApiClient, WechatAdmissionService, AppRegistrationRepository, and AuditService.

## Request flow

1. The JwtBearer handler validates the caller's access token against the current signing keys.
2. The controller resolves the account from the NameIdentifier claim and the application from `client_id`.
3. WechatApiClient exchanges the `code` for an OpenId through `sns/jscode2session`.
4. WechatAdmissionService writes the binding and the application admission inside one transaction,
   retrying once when a concurrent writer wins the unique index.
5. The caller receives a masked binding status; failures pass through centralized exception handling.

## Interface

Primary interface: /api/profile/wechat. The administrator counterpart is
/api/admin/apps/{appId}/wechat-policy and /api/admin/apps/{appId}/wechat-users.

## Persistence

Relevant tables: user_logins, app_wechat_accesses, accounts, refresh_tokens. The unique index on
(provider_name_normalized, provider_user_id) is what makes "one OpenId, one account" an invariant rather
than a check. app_wechat_accesses cascades from user_logins, so unbinding cannot leave orphaned
admissions.

## Design constraints

- Domain code does not depend on the web host.
- Controllers contain transport concerns, not persistence rules.
- Secrets and raw OpenId values are never included in diagnostic payloads.
- Async calls propagate CancellationToken.
- Provider-specific behavior must be covered by database contract tests.
