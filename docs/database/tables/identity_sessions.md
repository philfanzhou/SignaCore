# identity_sessions

Shared server-side identity sessions (canonical `PS-04`): the authoritative record behind the
`PS-18` browser identity cookie. The cookie carries only the opaque session id; the subject,
authentication time/method, activity, expiry, and revocation facts live exclusively in this table,
and any instance reads, updates, and revokes any instance's session through the shared database.

## Columns

- id (UUID, primary key; the opaque session id — fresh on every creation, never reused, and never
  written to SignaCore logs, metrics, traces, or exception messages)
- account_id (restrictive reference to accounts; indexed)
- password_credential_id (restrictive reference to password_credentials; indexed; creation proves
  the credential exists and belongs to the account)
- auth_method (fixed to `Password` in this phase)
- auth_time (authentication instant; immutable — it doubles as the creation time, so there is no
  second creation fact)
- last_seen_at (last activity write; equals auth_time at creation)
- idle_expires_at (auth_time + 30 minutes at creation; activity writes slide it, always capped at
  absolute_expires_at)
- absolute_expires_at (auth_time + 12 hours; never changed)
- revoked_at / revocation_reason (nullable pair; a database check constraint keeps them both null
  or both set)

## Relationships and invariants

- Both identity references are restrictive and non-nullable, created together with this table:
  deleting an account or password credential that session rows still reference fails, and no
  cascade exists in either direction. Cleanup never nulls a reference to enable a delete.
- A read classifies one row under a single captured UTC instant: missing, then revoked (whatever
  the expiry columns say), then absolute-expired, then idle-expired, else active. Boundaries are
  inclusive — an instant equal to a deadline is already expired — and reads never write: expiry is
  a time result, never a revocation, and a missing row is never invented.
- The activity write is one conditional update: only an unrevoked row inside both deadlines whose
  `last_seen_at` is at least one minute old is touched, and the new idle deadline is capped at the
  row's own absolute deadline. It never extends `absolute_expires_at`, never rewrites `auth_time`
  or the revocation columns, and never revives a revoked or expired session.
- Revocation is one conditional update on an unrevoked row: the first revocation's time and reason
  stay authoritative and later revocations change nothing. An expired but unrevoked row can still
  be revoked. The reason set is closed in the domain API (`logout`, `administrative`,
  `code_replay`); the database enforces only the time/reason pairing, not the value set, so later
  canonical events can add reasons without a schema change.
- A row lock (`SELECT ... FOR UPDATE` on PostgreSQL, a read inside the transaction on SQLite)
  exists for caller-owned transactions that write session-related state, enforcing the canonical
  order "lock the session first, then write code, family, or logout-request rows".
- Write operations join a caller-owned ambient transaction when one exists and commit or roll back
  with it; standalone writes run as one retryable unit inside the execution strategy. SQLite
  deployments are single-instance: the state machine holds under one writer, and multi-instance
  SQLite is not supported (`PS-22`).
- Cleanup deletes rows only once their idle expiry or revocation is older than the 24-hour
  retention window, as one transactional unit. A session past its own retention window is still
  kept while any retained `authorization_codes` row references it: the authorization-code cleanup
  segment runs before this one in the same round, so once the last referencing code is deleted the
  session becomes deletable.

The authoritative semantics are `PS-04` and its related rows in
[CanonicalSemanticModel.md](../../oidc/CanonicalSemanticModel.md); this page is a projection, not a
second rule set.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
