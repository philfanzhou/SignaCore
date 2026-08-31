# Interactive Persistence and Family Migration

**Status: target design.** Read the [directory boundary](./README.md), the
[canonical model](./CanonicalSemanticModel.md), and
[interactive refresh families](./RefreshTokens.md) first.

Canonical `PS-01` through `PS-23` own artifact relationships. This document projects only the
refresh-family additions and migration procedure needed by #97; it does not redefine the schemas
owned by authorization, session, logout, or client-policy implementation tasks.

## Current table and additive columns

The existing `refresh_tokens` table and every current column remain in place. In particular,
`token_value` stays the versioned one-way digest, `created_at`/`expires_at` stay the issued/expiry
facts, `is_revoked` stays explicit named-token revocation state, and the account, application,
LDAP/SMS/WeChat, and `source_app_id` bindings keep their current meanings.

#97 adds these columns symmetrically:

| Column | Shape | Relationship |
| --- | --- | --- |
| `family_id` | UUID, ultimately non-null | Root stores its own `id`; every interactive descendant stores that root id; every legacy row is a singleton root |
| `parent_id` | UUID, nullable | Immediate interactive parent; null for every root and every legacy row |
| `identity_session_id` | UUID, nullable | Non-null only for interactive members; restrictive reference to the `PS-04` session authority |
| `scope` | ASCII string(200), nullable | Canonical interactive family snapshot; null for legacy rows |
| `auth_time` | UTC instant, nullable | Original interactive session authentication time; copied unchanged to descendants; null for legacy rows |
| `consumed_at` | UTC instant, nullable | Successful interactive rotation fact; null for live/revoked interactive members and always null for legacy rows |

`is_revoked` and `consumed_at` are intentionally separate. A consumed member proves reuse; an
explicitly revoked or expired member does not. Revocation causes are closed audit/state outcomes
committed by the canonical event owner, not unbounded text copied from an input.

## Keys, indexes, and integrity

The migration retains the unique digest index and adds:

- a restrictive self-reference from `family_id` to the root `id`;
- a restrictive self-reference from `parent_id` to the immediate parent;
- a restrictive session reference from `identity_session_id`;
- one unique nullable index on `parent_id`, so an interactive parent has at most one child;
- lookup indexes on `family_id` and `identity_session_id` for family/session revocation;
- the restrictive nullable authorization-code `refresh_family_id` reference to a root created and
  linked by the same `EV-21` transaction.

That last reference is the single deferred one named by `PS-23`: #50 creates the nullable
`refresh_family_id` column with the authorization-code table, but no family root shape exists until
this migration, so the reference itself is added here. It is added last, after the backfill, and
both providers add it the same way. Every other authorization-code reference, including the non-null
restrictive session reference of `PS-05`, is created with that table by #50 and is not part of this
migration. The asymmetry cost of deferring is the reason `PS-23` defers nothing else: PostgreSQL adds
a reference to a populated table in place, while SQLite has to rebuild and copy that table, so the
two histories stop sharing one statement shape and the rebuild has to preserve every retained code
row. That cost is accepted only here, where the referenced root cannot exist earlier, and it is
bounded because `refresh_family_id` stays null until #98 writes the first interactive root.

No relationship cascades on delete. Cleanup must prove that code, session, root, parent, and
descendant references are no longer needed before deleting them. Account/application values keep
their established logical bindings; this migration does not retrofit unrelated current foreign
keys or rename/retype current columns.

Database checks require either a complete legacy marker (session, scope, auth time, and consumption
all null) or a complete interactive marker (session, scope, and auth time all non-null). Only an
interactive row may have `parent_id` or `consumed_at`. Domain writes additionally require a child,
parent, and root to have identical account/application/session/scope/auth-time values and require
the parent to belong to the named root. PostgreSQL/SQLite database-contract tests execute corrupt
raw inserts and repository writes to prove these invariants fail closed.

## Upgrade and backfill

The provider-specific Up migrations perform the same ordered operation:

1. Add the six columns as nullable without changing a current default or token value.
2. Set `family_id=id` for every existing row in one bounded provider-appropriate update. Leave
   `parent_id`, `identity_session_id`, `scope`, `auth_time`, and `consumed_at` null and preserve
   `is_revoked`, digest, expiry, admission bindings, application, and `source_app_id` byte-for-byte.
3. Make `family_id` non-null, add checks, restrictive references, and indexes only after the
   backfill succeeds.
4. Add the code-to-root reference only after every existing token has a traceable root.

The migration never decodes, hashes again, prints, or selects a raw token into application memory.
An older database that still contains plaintext values continues through the existing protected
startup rewrite after migration; that established path hashes each value once and preserves what
the client presents. Family backfill is independent of token representation.

New legacy issue/rotation/exchange writes must set `family_id=id` and keep every interactive marker
null. New interactive roots set `family_id=id`, session/scope/auth-time, and no parent; rotation
copies the root/bindings/deadline and sets the immediate parent. A partially upgraded writer is not
allowed: capability remains disabled until the code and both migration histories agree.

## Provider symmetry and concurrency contracts

PostgreSQL uses `uuid` and `timestamp with time zone`; SQLite uses the repository's existing GUID and
UTC-instant conversions. Names, nullability, maximum lengths, checks, unique relationships, delete
behavior, backfill values, and model snapshots are otherwise symmetric. Migrations are generated
against their own factories and never copied between providers.

Migration contract tests start from each provider's immediately previous history, seed live,
expired, revoked, digest-protected, plaintext-upgrade, and cross-application legacy rows, apply Up,
and compare every preserved value plus the singleton-root markers. Fresh-database tests compare the
final model shape. Down/Up round trips are tested only under the rollback gate below.

Runtime provider tests cover:

- two independent codes creating two distinct roots for one session/application;
- one parent allowing exactly one child;
- PostgreSQL multi-instance and SQLite single-instance double rotation (`SC-14`);
- execution-strategy failure before write, during insert/audit, and with ambiguous commit
  acknowledgement;
- family/session/code restrictive deletion and child-first whole-family cleanup;
- legacy same-app rotation and cross-app mint producing new singleton roots with unchanged wire
  results.

Every explicit transaction uses one captured UTC time and runs inside the provider execution
strategy (`PS-22`). Stable attempt identifiers and digests make retry verification idempotent; a
retry never regenerates externally different token bytes after a possibly successful commit.

## Retention and cleanup

Interactive consumed ancestors remain until the whole family can be removed, because deleting one
would turn a proved reuse into a missing token. Cleanup removes no individual root/ancestor while a
descendant, retained authorization code, or session relationship still references it. It removes a
family as one child-first unit only after all members are beyond their usable deadline, no retained
code needs its root link, and the canonical session/code retention rules permit deletion.

Legacy singleton cleanup preserves the current expired-or-revoked behavior. The self-reference is
handled within the same cleanup unit and must not make current rows immortal. Cleanup cancellation
or failure rolls back the unit and never nulls a relationship to force deletion.

## Deployment and rollback gate

#97 is an additive storage-only deployment. It backfills legacy rows but creates no interactive
family, leaves every current grant enabled, keeps `offline_access` absent from metadata, and can be
rolled back while no interactive marker exists (`AC-11`). The Down migration drops only the added
references, indexes, checks, and columns after verifying that condition.

After #98 has issued an interactive root, an in-place binary or schema downgrade is unsafe: an old
binary would see the same bearer row without understanding session, scope, consumption, or reuse and
could reinterpret it as legacy. Downgrade therefore fails closed while any interactive marker or
retained code-to-root link exists. Operators must first disable interactive refresh issuance,
revoke/drain interactive families, wait for required code/family retention, verify zero interactive
rows/references on both provider contracts, and only then run Down. Rolling the application binary
back while leaving such rows in a newer database is equally unsupported and must be blocked by the
capability/schema startup gate.

No migration rewrites an earlier history. #97 updates the PostgreSQL and SQLite model snapshots and
the public database table/migration documentation when it implements this design. This target
document changes neither history nor runtime behavior (`AC-14`).
