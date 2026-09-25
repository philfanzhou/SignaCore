# OIDC rate-limit budget schema

The persistence authority is [PS-24](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship).
Admission transitions, partition derivation and activation are still tracked by
[#71](https://github.com/philfanzhou/SignaCore/issues/71). Adding this table does not enable shared
admission, change HTTP responses, or satisfy the AC-13 production gate. SQLite keeps its existing
single-instance in-memory limiter.

Both provider histories add `AddOidcRateLimitBuckets` after their current predecessor. A fresh
installation or upgrade produces an empty budget table and expiry index; existing accounts,
applications, identity sessions, tokens, settings, installation, audit and key-ring rows are not
rewritten. Digest length is enforced by both databases; lowercase hex and HMAC correctness are
future store responsibilities. No raw partition identifier is stored.

Code rollback can leave the unused table in place. Down to this migration's **direct predecessor**
drops only the temporary budget table. Stop every future budget writer before doing so; operators
own migration permissions, coordination and backups. Do not cross historical irreversible
retirement migrations. After cancellation or an uncertain DDL outcome, read migration history and
physical schema before retrying; cancellation is not proof that committed DDL was rolled back.

Run the SQLite/PostgreSQL contract suite with Docker:

```sh
RUN_SIGNACORE_DATABASE_CONTRACTS=true dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj -c Release --filter FullyQualifiedName~OidcRateLimitSchemaDatabaseContractTests
```

The existing CI Database Contract Matrix selects this class. Tests cover fresh schema, valid and
invalid rows, transaction rollback, two independent connections racing for one key, additive
upgrade with populated existing artifacts, failures/cancellation after DDL execution, and Down/Up.
