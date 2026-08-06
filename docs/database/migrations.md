# Migrations

## Assemblies

| Provider | Migration project |
| --- | --- |
| PostgreSQL | `src/SignaCore.Database/SignaCore.Database.csproj` |
| MySQL / MariaDB | `src/SignaCore.Database.Migrations.MySql/SignaCore.Database.Migrations.MySql.csproj` |
| SQLite | `src/SignaCore.Database.Migrations.Sqlite/SignaCore.Database.Migrations.Sqlite.csproj` |

## History

The migration series creates the identity schema, adds login/audit records, normalizes identity values, enforces one OTP state per scope, binds refresh tokens to applications, enables application-scoped LDAP/SMS access, and adds OTP optimistic concurrency.

## Creating a migration

Select the appropriate startup factory and migration project, generate the migration with `dotnet ef`, review all generated SQL semantics, and repeat for every supported provider. Never copy a provider-specific migration blindly between projects.

## Deployment

The host provisions the database where supported and applies the selected provider's migrations at startup. Production deployments should back up data, use a database principal with the required migration permissions, serialize schema upgrades, and verify the EF migrations history after rollout.

## Rename note

Existing migration IDs and table names are unchanged. The new assemblies contain the same migration lineage under the `SignaCore` namespace, so an existing database remains compatible when the connection string is retained.
