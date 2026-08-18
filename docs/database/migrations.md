# Migrations

## Assemblies

| Provider | Migration project |
| --- | --- |
| PostgreSQL | `src/SignaCore.Database/SignaCore.Database.csproj` |
| SQLite | `src/SignaCore.Database.Migrations.Sqlite/SignaCore.Database.Migrations.Sqlite.csproj` |

## History

The migration series creates the identity schema, adds login/audit records, normalizes identity values, enforces one OTP state per scope, binds refresh tokens to applications, enables application-scoped LDAP/SMS access, adds OTP optimistic concurrency, enables application-scoped WeChat access, adds the per-application access-token audience mode, adds `system_settings` and `installation_state` so the business database becomes the configuration authority, and adds `app_exchange_trusts` plus `refresh_tokens.source_app_id` for cross-application refresh grants.

## Creating a migration

Select the appropriate startup factory and migration project, generate the migration with `dotnet ef`, review all generated SQL semantics, and repeat for every supported provider. Never copy a provider-specific migration blindly between projects.

The repository sets `UseArtifactsOutput`, so `dotnet ef` cannot find its own MSBuild targets under the
default path and fails with `The target "GetEFProjectMetadata" does not exist in the project`. Point it
at the artifacts intermediate directory instead, and use a tool version that matches the EF Core
packages in `Directory.Packages.props`:

```bash
dotnet ef migrations add <Name> \
  --project src/SignaCore.Database/SignaCore.Database.csproj \
  --msbuildprojectextensionspath artifacts/obj/SignaCore.Database
dotnet ef migrations add <Name> \
  --project src/SignaCore.Database.Migrations.Sqlite/SignaCore.Database.Migrations.Sqlite.csproj \
  --msbuildprojectextensionspath artifacts/obj/SignaCore.Database.Migrations.Sqlite
```

## Deployment

The host provisions the database where supported and applies the selected provider's migrations at startup. Production deployments should back up data, use a database principal with the required migration permissions, serialize schema upgrades, and verify the EF migrations history after rollout.

## Rename note

Existing migration IDs and table names are unchanged. The new assemblies contain the same migration lineage under the `SignaCore` namespace, so an existing database remains compatible when the connection string is retained.
