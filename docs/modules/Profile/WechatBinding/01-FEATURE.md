# WeChat Binding

## Purpose

Authenticated users bind a WeChat identity to their own account, inspect the binding, and remove it.
This is the only way an OpenId becomes usable for the `wechat_code` grant when the calling application
runs in `BindRequired` mode.

## Primary interface

/api/profile/wechat

## Acceptance summary

- A user authenticated with a JWT can bind, read, and unbind their own WeChat identity.
- An OpenId belongs to at most one account, and an account holds at most one OpenId.
- Binding admits the identity for the application that issued the caller's token, not for every application.
- Unbinding cascades the application admissions derived from that binding.
- Raw OpenId values never appear in responses or logs; only masked values do.

## Out of scope

Administrator-initiated binding. An OpenId is only knowable after the user authorizes, so administrators
revoke existing admissions instead of granting new ones.

## Related documents

- [Requirements](./02-SPEC.md)
- [Design](./03-DESIGN.md)
- [Tasks](./04-TASKS.md)
- [Tests](./05-TESTS.md)
- [Conventions](./06-CONVENTIONS.md)
