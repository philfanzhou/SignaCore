# Architecture

## Layers

```text
SignaCore.Host -----> SignaCore.Domain -----> SignaCore.Database
       |                                           ^
       +-----> provider migration assemblies ------+
```

- `SignaCore.Host` owns HTTP, middleware, configuration, discovery, observability, and SPA hosting.
- `SignaCore.Domain` owns authentication, claims, tokens, keys, SMS, LDAP, callbacks, and audit policy.
- `SignaCore.Database` owns EF Core entities, repositories, the unit of work, and PostgreSQL migrations.
- A provider-specific assembly owns SQLite migrations.

The host is the composition root and references its real dependencies explicitly. The repository does not keep an empty pass-through application assembly.

## Runtime design

The host loads configuration, initializes logging and discovery, selects the database provider, provisions and migrates the schema, initializes bootstrap applications and the administrator, and then serves the API and admin SPA. Central exception handling produces a stable JSON error envelope. Correlation middleware propagates `X-Correlation-ID`.

## Stable contracts

The SignaCore rename affects namespaces, assemblies, solution/project names, image identifiers, and deployment defaults. Routes, JSON fields, JWT claim names, and database table names remain stable to avoid unnecessary client and data migrations.

See [module designs](../modules/README.md) for feature-level details.
