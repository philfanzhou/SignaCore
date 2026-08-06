# Token Issuance

## Purpose

Clients exchange password, SMS, WeChat, LDAP, or refresh-token credentials for an RS256 JWT and a rotating refresh token.

## Primary interface

POST /api/auth/token

## Acceptance summary

- Authorized callers can complete the supported operation.
- Invalid input is rejected with the repository's standard API error envelope.
- Sensitive values are not written to logs or returned unintentionally.
- The behavior is covered by unit or integration tests.

## Out of scope

This feature does not change unrelated authentication protocols, database ownership, or downstream authorization policy.

## Related documents

- [Requirements](./02-SPEC.md)
- [Design](./03-DESIGN.md)
- [Tasks](./04-TASKS.md)
- [Tests](./05-TESTS.md)
- [Conventions](./06-CONVENTIONS.md)
