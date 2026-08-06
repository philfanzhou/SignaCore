# Refresh Token Revocation

## Purpose

Clients revoke a refresh token so it can no longer be exchanged for new credentials.

## Primary interface

POST /api/auth/revoke

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
