# ADR 0004: Drop MySQL/MariaDB Support and Adopt EF Core 10

- Status: Accepted
- Date: 2026-08-18
- Amends: [ADR 0001](./0001-multi-provider-persistence.md)

## Context

ADR 0001 committed SignaCore to PostgreSQL, MySQL/MariaDB, and SQLite. The MySQL/MariaDB adapter
depended on `Pomelo.EntityFrameworkCore.MySql`, the only EF Core provider that covers both MySQL and
MariaDB from a single package.

That dependency stopped moving. Pomelo's last commit landed on 2025-08-17 and its newest published
package remains an EF Core 9 provider; the maintainer's own EF Core 10 upgrade pull request has been
open since 2025-11-15 without merging. Because an EF Core provider must be built against a matching
EF Core major version, SignaCore could not move past EF Core 9 while it kept the Pomelo adapter, and
every other package in the stack — ASP.NET Core, the extensions libraries — is already on 10.x.

The alternatives each carried a cost that outweighed keeping the adapter:

- Oracle's `MySql.EntityFrameworkCore` ships an EF Core 10 provider, but targets MySQL rather than
  MariaDB, so adopting it would have silently narrowed a supported target.
- Building Pomelo from an unmerged branch and pinning a self-built package would put an unreviewed
  build into the dependency chain of an identity service.
- Staying on EF Core 9 indefinitely keeps the real exposure, which is an unmaintained data-access
  provider rather than the EF Core version itself.

No deployment uses the MySQL/MariaDB adapter.

## Decision

Withdraw MySQL and MariaDB as supported providers. Remove the `SignaCore.Database.Migrations.MySql`
migration assembly, the Pomelo package reference, and the MySQL-specific model configuration,
connection-string handling, database provisioning, migration locking, bootstrap options, and
contract-test matrix entries. Move EF Core and the Npgsql provider to 10.x.

PostgreSQL remains the provider for multi-instance operation; SQLite remains the single-instance
option.

## Consequences

- The supported provider set is PostgreSQL and SQLite. `Database:Provider` no longer accepts
  `MySQL` or `MariaDB`, and first-run setup no longer offers them.
- A schema change now accounts for two migration histories rather than three.
- The model no longer carries provider branches for character sets, collations, or `datetime(6)`
  instant storage; `timestamptz` and the SQLite Unix-microsecond conversion are the remaining cases.
- The contract matrix drops its MySQL and MariaDB containers, shortening the CI database job.
- An existing MySQL or MariaDB deployment is not upgradable in place. Its data must be migrated to
  PostgreSQL against a schema-equivalent target, since table and column names are unchanged.
- The dependency stack is on a single EF Core major again, so EF Core majors no longer need to be
  held back in Dependabot.
- Restoring MySQL/MariaDB later means adding an adapter, a migration assembly, and CI coverage under
  the ADR 0001 model, which is unchanged in that respect. It does not require a second ORM.
