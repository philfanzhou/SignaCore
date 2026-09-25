# Management bearer session schema

The [management bearer model in issue #360](https://github.com/philfanzhou/SignaCore/issues/360)
is the authority for credentials, lifecycle, trust boundaries, and activation stages.
This document covers only the additive schema delivered by
[task #382](https://github.com/philfanzhou/SignaCore/issues/382).

## Persistence contract

`management_bearer_sessions` stores a GUID primary key, a required unique `token_digest`
(maximum and checked length 71), and a required `account_id` reference to `accounts(id)`
with `ON DELETE CASCADE`. It has required `created_at` and `expires_at` instants and nullable
`revoked_at`. Indexes support digest lookup, account lookup, and expiry cleanup.

Checks enforce `expires_at > created_at` and either no revocation instant or
`revoked_at >= created_at`. Instants use the existing `ConfigureInstant` mapping:
PostgreSQL `timestamptz` and SQLite integer Unix microseconds. No plaintext credential,
password, application secret, username, or permission cache is stored in this table.

The database checks length and temporal ordering. It does not validate a digest prefix or
hexadecimal alphabet, enforce the future 15-minute lifetime, or authenticate a bearer.
Lifecycle services will enforce those rules as defined by the authoritative model.
There is no new handler, writer, route, DI registration, setting, or frontend activation in
this schema delivery. Existing Cookie, OIDC, and business JWT behavior is unchanged.

## Lifecycle service

[Task #383](https://github.com/philfanzhou/SignaCore/issues/383) adds an internal
`ManagementBearerSessionService` that issues, validates, revokes, and cleans up these rows,
registered in DI but not consumed by any endpoint, authentication scheme, or UI yet, so it enables
nothing. Each operation uses its own non-retrying `IdentityDbContext`; `CleanupWorker` deletes
rows expired for at least 24 hours in batches of at most 1000. Its contract suite is
`ManagementBearerSessionDatabaseContractTests`.

## Upgrade and rollback

Apply the provider's incremental `AddManagementBearerSessions` migration through the
existing deployment migration procedure, with the deployment owner's backup policy.
New installations and upgrades get an empty table. The migration creates only this table
and its indexes; existing account, application, identity session, token, settings,
installation, audit, and data-protection data are retained.

Reverting application code can leave the unused table in place. `Down` to the **direct
predecessor** drops only `management_bearer_sessions`, including its indexes, checks, and
foreign key, and permanently removes its short-lived session rows. After writers are
introduced, stop all writers before running `Down`. Do not cross older irreversible
retirement migrations. Reapplying `Up` creates an empty table again.

After interrupted or failed DDL, inspect the actual migration history and physical schema
before retrying or rolling back. Cancellation does not promise to undo a migration that
has already committed. The deployment owner is responsible for recovery and backups.

## Executable evidence

`ManagementBearerSessionSchemaDatabaseContractTests` runs the same three scenarios against
SQLite and a real PostgreSQL container:

- Fresh physical schema, model/snapshot parity, microsecond UTC round trips, nullable and
  non-null revocation, unique digest and primary key, orphan account and invalid value
  rejection, transaction rollback, and account deletion that cascades only its own sessions.
- A populated direct-predecessor database, fault and caller cancellation after DDL executes,
  observed history/schema recovery, upgrade, `Down`, and re-upgrade, comparing existing
  schema and complete row hashes at each boundary.
- Two independently opened connections competing for the same digest: exactly one insert
  succeeds and one row remains. This does not extend SQLite's supported deployment topology.

Run both providers (Docker required):

```bash
RUN_SIGNACORE_DATABASE_CONTRACTS=true dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj -c Release --filter FullyQualifiedName~ManagementBearerSessionSchemaDatabaseContractTests
```

The existing CI Database Contract Matrix selects this class through its
`DatabaseContractTests` name and enables PostgreSQL. Without the environment gate,
PostgreSQL cases are skipped; that run alone is not full schema acceptance.
