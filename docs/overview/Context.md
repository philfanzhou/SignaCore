# SignaCore Context

SignaCore provides centralized authentication and identity management for service-based systems. It issues RS256 JWTs, publishes JWKS, manages application and user identities, and owns authentication security data.

Primary implementation: .NET 10, ASP.NET Core, EF Core, PostgreSQL/SQLite, Vue 3, Consul, Serilog, OpenTelemetry, and Prometheus.

Canonical identifiers:

- Namespace and assemblies: `SignaCore.*`
- Solution: `SignaCore.slnx`
- Image and container: `signacore`
- Consul service name (optional discovery, disabled by default): `SignaCore`
- JWT issuer/audience: `SignaCore` / `SignaCore.Services`

Public API routes and database table names remain stable across the repository rename.
