# Database provider support decision

- Status: deferred for MySQL, MariaDB, SQL Server, and Oracle
- Decision date: 2026-09-30
- Scope: [SignaCore issue #463](https://github.com/philfanzhou/SignaCore/issues/463)

## Current support and evidence

SignaCore supports PostgreSQL 15 or newer and local-file SQLite. PostgreSQL provides the current
multi-instance deployment contract; SQLite remains single-instance. This decision changes no
provider ID, configuration, EF model, migration, installation flow, authentication, or deployment.

The current facts are visible in [DatabaseOptions](../../src/SignaCore.Database/DatabaseOptions.cs),
[provider selection and migration assemblies](../../src/SignaCore.Database/IdentityDatabaseOptionsExtensions.cs),
[the startup migration gate](../../src/SignaCore.Host/Migration/StartupMigrationGate.cs), and
[the real database CI matrix](../../.github/workflows/ci.yml). Existing
[migration and backup rules](migrations.md) remain authoritative.

[ServiceMantle v0.2.0](https://github.com/philfanzhou/ServiceMantle/releases/tag/v0.2.0) publishes six
database adapters. Its [pinned database contract](https://github.com/philfanzhou/ServiceMantle/blob/v0.2.0/README.md#database-target-preparation)
provides bootstrap validation, target observation and explicit preparation, deployment capabilities,
and migration leases. Those capabilities do not supply SignaCore's EF provider, schema, migrations,
transaction ownership, or identity-state concurrency proofs. An adapter package alone is insufficient
for a SignaCore support claim. References here use the released tag rather than upstream main.

## Decision and investigation order

No new runtime provider is selected. The frozen work has no named deployment owner requiring one
of these engines, no approved driver/version/license combination, and no SignaCore real-database CI
for them. All four are deferred, with explicit value hypotheses and different engineering gates.
Conditional investigation order is **MySQL → MariaDB → SQL Server → Oracle**: this orders an initial
engineering study, not production support or a release promise. A concrete supported deployment
requirement may change that order; no performance or cost comparison has been measured.

| Candidate | Value hypothesis to validate with a deployment owner | Decision and provider-specific limits |
| --- | --- | --- |
| MySQL | Reuse an operator's existing MySQL Community database estate and skills. | Defer until demand, EF10 driver and real CI exist. The pinned shared adapter accepts a restricted official MySQL Community product tuple, not arbitrary MySQL-compatible/cloud services. Prove character set, collation, identifier case and unique-index semantics on the exact target; shared preparation does not create users or grants. |
| MariaDB | Serve operators who already standardize on MariaDB without requiring a PostgreSQL service. | Defer independently from MySQL. The shared adapter declares MariaDB 10.11+ and a distinct provider identity; MySQL success cannot certify MariaDB. Prove its selected server/version, JSON representation, collation and concurrency independently. |
| SQL Server | Integrate with an estate whose DBAs and operational controls center on SQL Server. | Defer until a concrete deployment and real CI are owned. The shared adapter declares SQL Server 2019+ and a session-owned application-lock lease. Existing PostgreSQL DDL, filters, types, constraint classification and retry behavior require separate modeling; permission-limited target discovery must remain fail-closed. |
| Oracle | Serve an identified organization with an existing Oracle PDB and DBA support. | Defer; this requires the most distinct schema, privilege and CI investigation. The shared contract is Oracle 19c+ self-managed single-instance PDB, local password user and its same-named schema. RAC, cloud/Autonomous, common/root users, non-CDB, wallet/external/proxy authentication and transparent failover are outside that contract. Preparation grants neither object DDL/quota nor the migration-lock privilege. |

Oracle's exact limits and ownership are documented in the
[pinned Oracle decision](https://github.com/philfanzhou/ServiceMantle/blob/v0.2.0/docs/decisions/0001-oracle-provider-contract.md).
For all server engines, read the pinned
[same-server proof contract](https://github.com/philfanzhou/ServiceMantle/blob/v0.2.0/docs/contracts/server-database-identity.md)
before administrative preparation. A host name or similar connection string is not proof; unverified
proxy routing or session migration must not silently weaken the lease or creation boundary.

## Dependency and modeling gates

The [official EF provider catalog](https://learn.microsoft.com/en-us/ef/core/providers/) describes
major-version compatibility as a requirement. At this decision date it lists EF10 for
`Microsoft.EntityFrameworkCore.SqlServer` and `Oracle.EntityFrameworkCore`, while its MySQL/Pomelo
entries list EF8/9. This is an investigation signal, not certification of an exact package pair.
Before any dependency change, record a released package version compatible with this repository's
EF Core 10/.NET 10 versions, driver transitive dependencies, supported server builds, license and
redistribution terms, security maintenance, and rollback compatibility. Do not downgrade the whole
application to satisfy a candidate driver.

| Candidate | Driver candidates to investigate; no package selected | Required model and operational proof |
| --- | --- | --- |
| MySQL | `Pomelo.EntityFrameworkCore.MySql` or `MySql.EntityFrameworkCore`; verify released EF10 compatibility with vendor documentation. | UTC and precision; binary/case-sensitive canonical identity uniqueness; `utf8mb4` index sizes; JSON validation/query translations; generated values and optimistic concurrency; explicit transactions and deadlock handling. Record separate target/admin grants, product identity and `GET_LOCK` session-loss behavior. |
| MariaDB | `Pomelo.EntityFrameworkCore.MySql` with an explicitly verified MariaDB server/version; sharing a driver does not share the product claim. | Separate generated DDL and migration history; UTC, character/collation rules, JSON behavior, check constraints, unique keys and optimistic concurrency. Record MariaDB-specific preparation, grants and `GET_LOCK` lease loss. |
| SQL Server | `Microsoft.EntityFrameworkCore.SqlServer` and its pinned SQL client. | SQL dialect, Unicode/index lengths, UTC timestamp representation, case/collation, JSON mapping, concurrency tokens and filtered indexes; transaction isolation, deadlocks, retry replay and affected-row counts. Verify dedicated-session `sp_getapplock`, schema grants and connection routing. |
| Oracle | `Oracle.EntityFrameworkCore` and compatible `Oracle.ManagedDataAccess.Core`. | Schema/user ownership, identifier casing/limits, sequences/generated keys, UTC timestamps, string/empty/null semantics, JSON/large values and numeric concurrency tokens; own DDL/history and constraint classification. DBA-owned quota/object privileges, direct `EXECUTE ON SYS.DBMS_LOCK`, bounded session loss and nontransactional preparation recovery. |

Each candidate needs its own migration assembly/history and model snapshot, not copied PostgreSQL
SQL. A study must inventory every current table, constraint, restrictive foreign key, index and raw
SQL path, including shared settings, audit and Data Protection mappings. It must review transaction
boundaries against existing [OIDC ownership](../oidc/Ownership.md), migration leases and first-run
completion; provider retries must not replay a forbidden caller-owned transaction.

The study must name exact real CI images/server builds, CPU architecture, startup deadlines,
registry availability, permission setup, license acceptance and an owner able to keep the job
running. A mock-only suite, zero discovered tests, or gated skips cannot satisfy the production gate.
No effort, performance or license-cost numbers are asserted before that evidence exists.

## Required acceptance matrix

Every selected provider must pass these scenarios on its real supported server build. Existing
PostgreSQL and SQLite required checks remain green throughout; provider selection cannot alter
existing identities, routes, JSON, JWT claims or stored data.

| Scenario | Evidence required before production enablement |
| --- | --- |
| Fresh installation | Empty, missing and existing targets; explicit authorized preparation, wrong product/version/owner, missing privileges, no accidental mutation of existing targets; bootstrap → migrations → setup → Completed and normal-host container smoke. |
| Upgrade and recovery | Replay its complete migration history; upgrade supported older release with representative retained identity data; bridge/retirement restrictions; fault and cancellation at each committed boundary; verified backup restore and restart. |
| Shared settings and audit | Single authoritative settings aggregate, protected values, version conflicts, transactional update/audit rollback, snapshot activation and restart; no credential values in errors, logs or CI output. |
| Data Protection and keys | Durable encrypted shared ring, matching root key across hosts, cross-host cookie/session use, key rotation/JWKS continuity, wrong-key and database-failure rejection. |
| Refresh and OIDC state | Exactly one winner for concurrent refresh/code consumption; replay/revocation, logout, SMS continuation/admission, rate-limit contention and identity canonicalization; deterministic overlapping requests on two hosts. |
| Migration and deployment | Explicit SingleInstance/MultiInstance capability, two competing startup executors, held-lease recheck, session loss, cancellation, deadlines and safe fixed diagnostics; never silently migrate without the required lease. |
| Fault and cancellation | Original request token propagation, disconnect/timeout/deadlock and commit-acknowledgment uncertainty; bounded cleanup, preserved audit/business transaction boundary and restart convergence, no claim of undoing already committed effects. |
| Container operations | Real image bootstrap/setup/normal health, graceful shutdown, persistence after restart, configured permissions and backup/restore runbook; hard-fail CI result counts with no gated skips. |

A provider's migration rollback requires a provider-specific documented proof. Binary rollback is
permitted only while the previous release can read the resulting schema and data; otherwise stop
all writers and restore the verified database/root-key/bootstrap backup set. Switching database
engines is a separate data-migration project, not a provider flag change. Mixed-version operation
needs explicit compatibility evidence, especially across irreversible historical migrations.

## Decision walkthrough

The following tabletop paths were evaluated against this decision; they are planning results,
not executions against candidate databases or support certifications.

| Inputs to the decision | Path and result |
| --- | --- |
| Current frozen work: no named deployment requirement or candidate CI, even though shared adapters are released | The revisit gate fails for all four candidates; retain PostgreSQL/SQLite and create no runtime implementation tasks. |
| A MySQL deployment owner appears, but only an EF9 driver is demonstrated for this EF10 application | Demand alone cannot pass dependency compatibility; defer implementation until a released compatible combination is documented, without downgrading the application. |
| A MariaDB request supplies successful MySQL CI instead of a MariaDB server build | Product-specific acceptance fails; MySQL preparation and concurrency results cannot enable MariaDB. Require its own real-server matrix. |
| An Oracle PDB can be prepared with CREATE SESSION but the target lacks object privileges/quota or DBMS_LOCK access | Preparation does not imply migration readiness. Keep activation off, record DBA gates and verify supported topology before schema/lease tasks. |
| A SQL Server request supplies all three revisit inputs but has not proven refresh/OIDC two-host concurrency or backup recovery | Select the investigation, create the dependent task chain below, and keep production activation off until every task's real acceptance passes. |

## Revisit triggers and subsequent task split

Reopen the decision only when a maintainer records all three in a tracked issue:

1. A named deployment owner, exact engine/version/topology and concrete reason the current supported
   engines do not meet that deployment's needs.
2. A released EF10/driver/server combination with documented version and license compatibility,
   plus a maintainer responsible for its continuing support.
3. Stable real-database CI/container access, required DBA permissions, license/architecture review
   and an owner of backup/recovery acceptance.

After those triggers are verified, select exactly one initial provider and create independently
reviewable tasks with native dependency links:

1. **Schema and new installation:** dependency pins, product/target validation, preparation,
   provider ID, model/migration assembly, bootstrap UI and fresh-install CI; activation remains off.
2. **Upgrade and rollback:** complete historical upgrade evidence, version compatibility matrix,
   irreversible operations, verified backup recovery and operator runbook; depends on task 1.
3. **Identity state and concurrency:** the full settings/audit/DP/refresh/OIDC/multi-host and
   cancellation/failure matrix above; depends on tasks 1 and 2.
4. **Production enablement:** required hard-fail CI, container smoke, deployment limits and support
   documentation; depends on all previous acceptance evidence.

No implementation issues are created by this deferred decision. The existing SQLite input-boundary
work ([#461](https://github.com/philfanzhou/SignaCore/issues/461)) remains separate. Rollback of this
planning document changes no runtime behavior or existing database guarantees.
