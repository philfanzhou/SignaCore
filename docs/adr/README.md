# Architecture Decision Records

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](./0001-multi-provider-persistence.md) | Accepted | Use EF Core provider adapters for PostgreSQL, MySQL/MariaDB, and SQLite |
| [0002](./0002-database-backed-configuration.md) | Accepted | Store global configuration in the business database, with a writable protected bootstrap file and web-based setup |
| [0003](./0003-cross-application-refresh-grant.md) | Accepted | Allow a refresh token to be exchanged across applications over an administered directed trust edge, minting single-hop |
