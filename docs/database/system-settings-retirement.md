# System settings retirement

The `RetireSystemSettings` migration (PostgreSQL and SQLite, ServiceMantle issue #556) removes the
legacy `system_settings` table and, with it, the last runtime consumers of the legacy configuration
store: the legacy settings store and snapshot, the one-shot legacy row migration, the legacy
configuration protector, and the resolver's legacy-row check. The shared `service_settings`
aggregate is the only persisted configuration authority, exactly as since the runtime switch.

## What the guard protects

Dropping the table is irreversible, so the drop is guarded on both providers. The guard runs inside
the migration transaction, before the drop, and decides on **existence only** — it never reads a
setting value:

> Refuse when `system_settings` holds any rows **and** the shared `service_settings` aggregate of
> service `signacore` does not exist.

Consequences per starting state:

| Database state | Outcome |
| --- | --- |
| Fresh (or no legacy table yet) | The full chain creates the empty legacy table during history replay and the guard lets the drop proceed. |
| Legacy table empty, any aggregate state | Guard passes; the drop proceeds. |
| Legacy rows present, aggregate exists (a bridge-completed database) | Guard passes; the drop removes the already-migrated source; the aggregate is untouched. |
| Legacy rows present, no aggregate | **Refused.** The migration rolls back inside its transaction: no row is deleted, no half-completed drop survives, and the migration is not recorded as applied. |

The guard never interprets "one row exists" as "the migration would have succeeded". Verifying that
the shared snapshot actually activates (a complete, decryptable aggregate) is the bridge build's
job, not the guard's.

## Required upgrade path (staged deployment)

1. **Back up the database and the root key** before applying any version in this sequence. The
   retirement drop is irreversible; the only rollback is restoring that backup.
2. Run a **bridge build** — any build that still migrates `system_settings` into the shared
   aggregate; the minimum is a build including commit `e45e97416e491d7dfefe984e4ed557d480d14ca0`.
   There is no required version number; the commit is the floor.
3. While the bridge build runs, confirm the shared snapshot activates: startup logs
   `Loaded configuration snapshot` and the admin console's settings page serves current values.
   Keep the bridge build running until every old instance has been stopped in the next step.
4. **Stop every SignaCore instance** of the old versions. Mixed running is forbidden during this
   window: instances of pre-retirement builds still read the legacy table, while post-retirement
   builds drop it.
5. Apply the retirement version. Its startup pre-check and the in-migration guard both verify the
   bridge precondition before anything is deleted.

## How a refusal surfaces

- **Through startup** (the normal path): startup stops before the migration gate with the fixed,
  value-free message naming the bridge requirement and this document. Nothing was modified.
- **Through `dotnet ef database update` or another direct migration runner**:
  - PostgreSQL raises `refusing to drop system_settings: the table still holds rows that were
    never migrated into the shared service_settings aggregate of service signacore; upgrade
    through a bridge build first`.
  - SQLite fails the fixed CHECK constraint `system_settings_retirement_guard`, which the refusal
    message names.
- A refusal is deterministic: retrying against the same unmigrated database refuses again. Fix the
  state (run the bridge build) instead of retrying.

## Cancellation and partial failure

The guard and the drop run inside the provider's migration transaction. A failure, crash, or caller
cancellation during the migration leaves no half-completed drop: either the transaction committed
(the table is gone) or it rolled back (the table and every legacy row are intact and the retry
starts clean). After the drop has committed, cancellation of a later step never "undoes" it — the
next start reads the migration history and the aggregate. Caller cancellation keeps its original
token throughout.

## Downgrade

`Down` deliberately throws a fixed `NotSupportedException`: recreating an empty `system_settings`
table would masquerade as a restore while the retired rows stay gone. To go back, restore the
database backup taken before step 5 — as a set with the root key and the bootstrap file of that
point in time. Binaries older than the retirement build can read a restored pre-retirement
database; they cannot read a database whose migration history contains `RetireSystemSettings`.

## What is not guaranteed

- Automatic crossing over the bridge build: an operator must run it (this document's sequence).
- Recovery of legacy row data after the drop: the source rows are deleted; only a backup restores
  them.
- Old binaries reading a post-retirement database (see Downgrade).
- Automatic compensation of unknown commit results: a lost confirmation is re-decided by the next
  start from the persisted migration history and aggregate, never guessed.
