# SignaCore Collaboration Guidelines

SignaCore is a .NET 10 identity and authentication service with a Vue 3 admin console. It handles authentication, RS256 JWTs, refresh tokens, JWKS, the management API, auditing, and PostgreSQL/SQLite persistence.

## Maintenance

- This file is the single entry point for the AI collaboration workflow, review policy, and project boundaries.
- Codex reads this file directly; Claude Code v2.1.277+ also reads it directly, without a root `CLAUDE.md` import.
- `CONTRIBUTING.md` is the engineering entry point for all contributors.
- `docs/`, `CONTEXT.md`, the ADRs, and `SECURITY.md` are the sources of truth for their domains; before implementing, confirm whether they describe target behavior or current fact.

## Documentation and communication language

- Process and constraint documents, GitHub issue/PR bodies, and reviews use English throughout.
- Progress updates, final reports, issue/PR bodies, and reviews use everyday English: state the object, action, and condition directly; do not paste internal process jargon or translate word for word. Keep the necessary technical terms and explain them when needed.
- PR titles use the English conventional commit format (`feat:` / `fix:` / `docs:` / `test:` / `refactor:` / `chore:` etc.).
- `README.md`, `docs/`, code comments, automation comments, API/exception messages, and user-facing text stay in English; this is the repository's existing public contract.
- The only exception: the UI text rendered by the hosted login page (`/oauth2/login`) provides `zh-CN` and `en` according to `Accept-Language`, defaulting to `en`; see ADR 0006. Its API, logging, audit, and exception text still uses English.
- Code identifiers, configuration keys, JWT claims, HTTP routes, commands, and commit messages stay as-is/English.

## Project boundaries and architecture

- The host composes `SignaCore.Domain`, `SignaCore.Database`, and the provider-specific migration projects; Domain must not depend on ASP.NET Core transport types.
- Downstream systems integrate over HTTP discovery, JWKS, and the API, or reference the official client package `SignaCore.Client.AspNetCore` (the only assembly in this repository downstream systems may reference; see `docs/adr/0007-official-hosted-login-client-package.md`); server-side assemblies such as Host, Domain, and Database must not be referenced by downstream systems. Pure HTTP integration remains supported and documented.
- Keep the `SignaCore` root namespace and the project/assembly names consistent; public routes, JSON fields, claims, and existing database table names are stable by default; breaking changes require an explicit migration and a compatibility plan.
- Global business configuration lives in the shared `service_settings` single aggregate (see `docs/development/SharedSettings.md`) and is maintained through the admin pages after first-time installation and authentication; apart from the provider/version/connection string needed to open the database and the external root key, do not push new business configuration into `appsettings.json`.
- PostgreSQL migrations live in `src/SignaCore.Database`, SQLite migrations in `src/SignaCore.Database.Migrations.Sqlite`; any schema change must consider both migration histories.
- Optional Consul discovery, OpenTelemetry, Prometheus, Serilog/Loki, and container startup behavior are operational contracts; when changing them, update the documentation and smoke tests in step.

## Security constraints

- Never commit or log credentials, application secrets, OTPs, refresh tokens, authorization headers, private signing keys, master keys, connection strings, or personal data.
- Do not expose or send back administrator credentials, signing private keys, root keys, or tokens; logs and test output must be redacted.
- Do not write business models, brand names, integration details, or validator configuration for a specific consumer; examples use neutral role names such as `OrderService`.
- Use UTC times and propagate cancellation tokens; behavior changes to authentication, authorization, key rotation, refresh tokens, JWKS, and the first-time installation flow require accompanying security/contract tests.

## Change and verification

Run the minimum sufficient verification for the change's risk:

```bash
dotnet restore SignaCore.slnx
dotnet build SignaCore.slnx --configuration Release --no-restore
dotnet test tests/SignaCore.Tests/SignaCore.Tests.csproj --configuration Release --no-build --no-restore
dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj --configuration Release --no-build --no-restore

npm --prefix src/SignaCore.Admin ci
npm --prefix src/SignaCore.Admin run test:coverage
npm --prefix src/SignaCore.Admin run build
```

When PostgreSQL/SQLite schema, authentication, the HTTP contract, configuration, images, or startup scripts are involved, run the corresponding migration, integration, and container smoke tests, and explicitly wait for CI verification when they cannot run locally.

## Security and change discipline

- Before adding dependencies or changing public APIs, the database, configuration, or deployment, first explain the compatibility, migration, and rollback impact.
- Before committing, check English documentation links, template formatting, secrets, migration symmetry, and repository state.
