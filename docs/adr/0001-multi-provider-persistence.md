# ADR 0001: Multi-provider Persistence

- Status: Accepted
- Date: 2026-07-30

## Context

SignaCore must support PostgreSQL, MySQL/MariaDB, and SQLite without maintaining separate domain or repository implementations. Provider differences affect connection parsing, database creation, server-version selection, migrations, SQL types, locking, and some schema operations.

## Decision

Use EF Core as the only ORM and data-access stack. Keep the model and repositories in `SignaCore.Database`; keep PostgreSQL migrations there; use `SignaCore.Database.Migrations.MySql` and `SignaCore.Database.Migrations.Sqlite` for provider-specific migrations. Select the provider from `Database:Provider` and validate its required settings at startup.

## Consequences

- Domain and repository code remain provider-neutral.
- Each provider needs an independent migration history and contract tests.
- Schema changes must be generated and reviewed for all providers.
- Provider-specific startup provisioning and migration locking remain host concerns.
- Supporting a new provider requires an adapter, migration assembly, deployment configuration, and CI coverage; it does not require a second ORM.

## Compatibility

The SignaCore rename changes migration assembly names and CLR namespace metadata, but not table names or existing migration identifiers. Existing databases remain usable when the connection string points to them.
