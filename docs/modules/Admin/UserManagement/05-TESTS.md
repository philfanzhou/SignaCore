# User Management: Test Plan

## Required coverage

Tests should cover creating password and phone users, paging and filtering, editing remarks, status changes, validating LDAP inputs, and duplicate identities.

## Test layers

- Unit tests isolate policy and error branches with xUnit and Moq.
- HTTP integration tests run the host through WebApplicationFactory.
- Database contract tests verify PostgreSQL and SQLite behavior where provider differences matter.

## Given-When-Then baseline

- **Given** a valid caller and valid input, **when** the operation runs, **then** it succeeds and persists or returns the expected state.
- **Given** invalid credentials or input, **when** the operation runs, **then** it fails without leaking sensitive details.
- **Given** cancellation or an infrastructure failure, **when** execution stops, **then** the failure is observable and no partial unsafe state remains.

## Administrator reset evidence

- `AdminPasswordResetEndpointTests` uses real HTTP authentication for Cookie/Bearer administrators,
  anonymous callers, ordinary user JWTs, application credentials, forged role claims, and management
  operators without Admin permission. It verifies exact input, standard missing/null/empty/blank
  password errors, missing accounts, zero/multiple credentials, no rejection writes, and new/old
  password login behavior without changing another account. Cookie and Bearer administrators can
  reset to short passwords and passwords missing uppercase letters, lowercase letters, or digits.
- `AdminPasswordResetDatabaseContractTests` runs SQLite and PostgreSQL migrations and proves hash/audit
  atomicity with a short, lowercase-only password, audit/save failure, cancellation before commit,
  affected-row rejection, disabled/locked state and session/token preservation, and ordered successful
  overlapping resets. PostgreSQL runs with `RUN_SIGNACORE_DATABASE_CONTRACTS=true` and Testcontainers;
  skipped tests do not validate it.
- Admin API and composable tests verify confirmation validation, exact payload, duplicate prevention,
  captured target, stale completion isolation, errors, cancel/close/account-switch clearing, and the
  hidden entry for accounts without a local password. They also cover submission of passwords that
  bypass the normal policy and the dialog's explanation of the exception.
- Existing create, self-service password-change, and login tests remain regression coverage. There is
  no schema, key, configuration or deployment change requiring new migration/key/smoke behavior.
