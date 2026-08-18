# Callback Registration: Test Plan

## Required coverage

Tests should cover valid registration, missing application authentication, malformed URLs, disallowed hosts, and updates to an existing registration.

## Test layers

- Unit tests isolate policy and error branches with xUnit and Moq.
- HTTP integration tests run the host through WebApplicationFactory.
- Database contract tests verify PostgreSQL and SQLite behavior where provider differences matter.

## Given-When-Then baseline

- **Given** a valid caller and valid input, **when** the operation runs, **then** it succeeds and persists or returns the expected state.
- **Given** invalid credentials or input, **when** the operation runs, **then** it fails without leaking sensitive details.
- **Given** cancellation or an infrastructure failure, **when** execution stops, **then** the failure is observable and no partial unsafe state remains.
