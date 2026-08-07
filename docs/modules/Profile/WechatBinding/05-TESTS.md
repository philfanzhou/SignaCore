# WeChat Binding: Test Plan

## Required coverage

Tests should cover binding a new OpenId, idempotent rebinding, an OpenId already owned by another account,
an account already bound to a different OpenId, a disabled account, unbinding with admission cascade,
unbinding when nothing is bound, and a disabled application policy.

## Test layers

- Unit tests isolate policy and error branches with xUnit and Moq.
- HTTP integration tests run the host through WebApplicationFactory.
- Database contract tests verify the unique index, the transaction, and the cascade on real SQLite
  (`WechatAdmissionDatabaseContractTests`); PostgreSQL and MySQL/MariaDB share the same model.

## Given-When-Then baseline

- **Given** an authenticated user and a valid WeChat code, **when** binding runs, **then** the OpenId is
  bound and admitted for the calling application.
- **Given** an OpenId already bound elsewhere, **when** binding runs, **then** it fails with HTTP 409 and
  the existing binding is untouched.
- **Given** a revoked admission, **when** the user logs in again or rebinds, **then** access stays
  revoked; only an administrator restore reactivates it.
- **Given** cancellation or an infrastructure failure, **when** execution stops, **then** the failure is
  observable and no partial unsafe state remains.
