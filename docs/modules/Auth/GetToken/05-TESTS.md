# Token Issuance: Test Plan

## Required coverage

Tests should cover each grant type, invalid application credentials, lockout, app binding, refresh rotation, callback claim enrichment, and bootstrap-admin role preservation.

Cross-application refresh grants additionally require: rejection without a trust edge, admission with one, the source token surviving the exchange, non-composition across two hops, direction, and admission derived as `ExchangeGranted` only under an auto-provisioning admission mode.

## Test layers

- Unit tests isolate policy and error branches with xUnit and Moq.
- HTTP integration tests run the host through WebApplicationFactory.
- Database contract tests verify PostgreSQL, MySQL/MariaDB, and SQLite behavior where provider differences matter.

## Given-When-Then baseline

- **Given** a valid caller and valid input, **when** the operation runs, **then** it succeeds and persists or returns the expected state.
- **Given** invalid credentials or input, **when** the operation runs, **then** it fails without leaking sensitive details.
- **Given** cancellation or an infrastructure failure, **when** execution stops, **then** the failure is observable and no partial unsafe state remains.
