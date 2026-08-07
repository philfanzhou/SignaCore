# WeChat Binding: Requirements

## Overview

Authenticated users manage the WeChat identity bound to their own account.

## Functional requirements

1. `GET /api/profile/wechat` returns whether the account is bound and a masked OpenId.
2. `POST /api/profile/wechat` exchanges a WeChat `code` for an OpenId and binds it to the caller's account.
3. `DELETE /api/profile/wechat` removes the binding and every application admission derived from it.
4. The calling application is resolved from the `client_id` claim of the caller's token; binding is refused
   when that application has `wechat_login_mode = Disabled`.
5. Binding an OpenId that already belongs to another account returns HTTP 409.
6. Binding a second, different OpenId to an already-bound account returns HTTP 409; rebinding requires an
   explicit unbind first.
7. Re-binding an OpenId whose application admission was revoked does **not** reactivate it; the bind is
   refused with HTTP 403. Revocation is administrator state, restored only through
   `POST /api/admin/apps/{appId}/wechat-users/{loginId}/restore`.
8. Bind and unbind are recorded in the audit log.

## Security requirements

The account identifier comes from the validated JWT, never from a caller-supplied account id. The
application scope comes from the token's `client_id` claim, never from the request body.

WeChat credentials (`WeChat:AppId`, `WeChat:AppSecret`) and raw OpenId values are never logged or
returned. All logs and errors must redact passwords, application secrets, refresh tokens, OTP values,
authorization headers, and private key material.

## Data

The feature owns user_logins rows whose provider is `WeChat` and the matching app_wechat_accesses rows.
Database access remains behind the WechatAdmissionService/IdentityDbContext boundary.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore
rename. Only product, namespace, assembly, image, and deployment identifiers changed.
