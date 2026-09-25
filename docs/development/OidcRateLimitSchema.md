# OIDC rate-limit budget schema

The persistence authority is [PS-24](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship).
Admission transitions and partition derivation are tracked by
[#71](https://github.com/philfanzhou/SignaCore/issues/71); the HTTP contract is in the
[OIDC security contract](../oidc/Security.md#rate-limit-contract). On PostgreSQL this table is the
shared budget of the six interactive OIDC policies. SQLite never writes it and keeps its
single-instance in-memory limiter.

Both provider histories add `AddOidcRateLimitBuckets` after their current predecessor. A fresh
installation or upgrade produces an empty budget table and expiry index; existing accounts,
applications, identity sessions, tokens, settings, installation, audit and key-ring rows are not
rewritten. Digest length is enforced by both databases; lowercase hex and HMAC correctness are
store responsibilities. No raw partition identifier is stored.

The PostgreSQL budget store (`PostgreSqlOidcRateLimitStore`) and its HMAC partitioner
(`OidcRateLimitPartitioner`) are registered only for PostgreSQL. Each protected request runs one
auto-committed statement on the store's own connection, outside every EF retry strategy; the cleanup
worker deletes rows whose window expired more than 24 hours ago in bounded batches. The store's
contract suite is `OidcRateLimitStoreDatabaseContractTests`; the host wiring is covered by
`OidcDistributedRateLimitDatabaseContractTests`.

Code rollback can leave the unused table in place; a release without the shared store goes back to
per-process budgets, so the cross-replica budget no longer holds. Down to this migration's **direct predecessor**
drops only the temporary budget table. Stop every future budget writer before doing so; operators
own migration permissions, coordination and backups. Do not cross historical irreversible
retirement migrations. After cancellation or an uncertain DDL outcome, read migration history and
physical schema before retrying; cancellation is not proof that committed DDL was rolled back.

Run the SQLite/PostgreSQL contract suite with Docker:

```sh
RUN_SIGNACORE_DATABASE_CONTRACTS=true dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj -c Release --filter FullyQualifiedName~OidcRateLimitSchemaDatabaseContractTests
RUN_SIGNACORE_DATABASE_CONTRACTS=true dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj -c Release --filter FullyQualifiedName~OidcDistributedRateLimitDatabaseContractTests
```

The existing CI Database Contract Matrix selects these classes. Tests cover fresh schema, valid and
invalid rows, transaction rollback, two independent connections racing for one key, additive
upgrade with populated existing artifacts, failures/cancellation after DDL execution, and Down/Up.
