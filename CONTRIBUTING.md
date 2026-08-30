# Contributing to SignaCore

Thank you for improving SignaCore. Keep changes focused, preserve public contracts unless the change is explicitly breaking, and write contributor-facing text in English.

## Development workflow

1. Create a branch from `main`.
2. Restore and build the root solution.
3. Add or update tests for behavior changes.
4. Update documentation and configuration examples when behavior changes.
5. Open a pull request describing the problem, the approach, compatibility impact, and verification performed.

```bash
dotnet restore SignaCore.slnx
dotnet build SignaCore.slnx --configuration Release
dotnet test tests/SignaCore.Tests/SignaCore.Tests.csproj --configuration Release
dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj --configuration Release
npm --prefix src/SignaCore.Admin ci
npm --prefix src/SignaCore.Admin audit --audit-level=high
npm --prefix src/SignaCore.Admin run test:coverage
npm --prefix src/SignaCore.Admin run build
```

Docker is required for the complete database contract matrix and image smoke checks.

## Protocol and stateful design work

Treat a change as feature-level work when it spans three or more public protocol surfaces, three or more stateful artifacts, or couples several of transaction/concurrency, migrations, sensitive-data flow, and capability activation. If that work cannot be reduced to one independently verifiable slice, use a feature/XL tracker with dependency-linked task issues. Trackers do not receive implementation pull requests.

Before a complex protocol or state task is marked ready, provide one canonical semantic model covering event-to-artifact outcomes, persistence relationships, external inputs, sensitive values across trust boundaries, and staged capability activation. Explanatory prose should reference that model rather than duplicate state rules in several documents. Validate the model with end-to-end scenarios; Markdown, link, language, and existing-code CI checks do not establish semantic correctness.

At the third review round, stop implementation and audit both scope and semantic closure. If cross-document, cross-state, or data-flow contradictions continue to appear, stop incremental patching, remove ready status, and split the work or rebuild the canonical model. Commit traceability alone is not evidence that a feature-sized issue is a valid task.

## Database changes

Schema changes must include reviewed migrations for PostgreSQL and SQLite. Keep existing migration identifiers intact and verify each provider's contract tests.

## Security

Do not open public issues for vulnerabilities or include live secrets in tests, logs, screenshots, or pull requests. Follow [SECURITY.md](SECURITY.md) for private reporting.
