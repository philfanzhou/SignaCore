# Repository Structure

SignaCore uses a conventional repository layout so that source, tests, documentation, and automation have clear ownership.

```text
.
|-- .github/                 GitHub Actions and dependency automation
|-- docs/                    Architecture and operational documentation
|-- src/
|   |-- SignaCore.Admin/     Vue administrative console
|   |-- SignaCore.Database/  EF Core model, repositories, PostgreSQL migrations
|   |-- SignaCore.Database.Migrations.MySql/
|   |-- SignaCore.Database.Migrations.Sqlite/
|   |-- SignaCore.Domain/    Authentication and identity behavior
|   `-- SignaCore.Host/      ASP.NET Core composition root and container file
|-- tests/
|   |-- SignaCore.Tests/
|   `-- SignaCore.IntegrationTests/
|-- Directory.Build.props   Shared .NET build settings
|-- Directory.Packages.props Central NuGet versions
|-- global.json             .NET SDK selection policy
`-- SignaCore.slnx          Root solution
```

Production code belongs under `src`, tests under `tests`, and long-form documentation under `docs`. Keep repository-wide build settings out of individual project files unless a project genuinely needs an exception. Add NuGet versions to `Directory.Packages.props`; project files should declare package usage without repeating versions.

`SignaCore.Host` is the composition root. It references Domain, Database, and the provider-specific migration assemblies explicitly. Do not add pass-through projects that contain no implementation solely to create another layer name.

Generated outputs belong under `artifacts`, `bin`, `obj`, or the frontend `dist` directory and must remain untracked.
