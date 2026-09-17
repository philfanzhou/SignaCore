# authorization_codes

Shared short-lived authorization codes (canonical `PS-05`). A code is created inside the login
success transaction from an accepted continuation and an authenticated identity session, and is
redeemed at most once by the token endpoint on any instance, using only the shared database.

## Columns

- id (UUID, primary key; public record id, safe in diagnostics)
- code_digest (versioned SHA-256 digest, unique index; the plaintext 43-character code is returned
  exactly once at creation and never persisted)
- app_registration_id / account_id (restrictive references; the account id always equals the
  referenced session's account id — guaranteed by the only writer, the domain store)
- identity_session_id (restrictive reference to identity_sessions; indexed; the token endpoint
  locks the session before the code)
- redirect_uri (snapshot of the exact registered canonical redirect URI value, compared ordinally
  at redemption — `EV-12`/`IN-23`)
- scope (canonical space-delimited scope snapshot)
- nonce (byte-for-byte snapshot)
- code_challenge (S256 challenge snapshot; the PKCE verifier is never stored)
- auth_time (copied from the referenced session at creation)
- created_at / expires_at (creation plus the fixed 60-second code lifetime)
- consumed_at (nullable; written at most once by the atomic consumption)
- refresh_family_id (nullable, no reference, no index; reserved for the interactive refresh family
  link — a database check constraint requires consumed_at to be set whenever it is not null)

## Relationships and invariants

- All three references (application, account, identity session) are restrictive and non-nullable,
  created together with this table: deleting a referenced application, account, or session while a
  code row exists fails, and no cascade exists in either direction. Cleanup deletes code rows only
  by retention and never nulls a reference.
- A read classifies one plaintext code under a single captured UTC instant: a malformed shape, a
  missing digest, or a failed constant-time comparison share the single `missing` answer; a
  consumed row is `consumed` whatever the clock says (an expired-but-retained consumed code is
  still a replay); then `expired` — the boundary is inclusive; otherwise `unconsumed`. Reads never
  write, and unvalidated raw input never becomes a query key.
- Binding verification is pure: the client id must match, the redirect URI must equal the snapshot
  ordinally, and the PKCE verifier (43–128 ASCII `[A-Za-z0-9._~-]`) must hash to the stored S256
  challenge under a constant-time comparison. Any mismatch returns false without distinguishing
  the reason; scope is not a redemption input.
- Consumption is one atomic conditional update of the unconsumed, unexpired row, so at most one
  concurrent consumer commits (`SC-13`). Expiry is never recorded as consumption. Inside a
  caller-owned transaction consumption commits or rolls back with the surrounding redemption
  transaction (`EV-21`); after a rollback the code is legitimately redeemable again (`EV-26`), and
  a committed consumption stays authoritative.
- The code row lock (`SELECT ... FOR UPDATE` on PostgreSQL, a read inside the transaction on
  SQLite) requires a caller-owned ambient transaction and returns a no-tracking snapshot without
  clearing the change tracker, so the session locked first in the canonical session-then-code
  order stays tracked (`EV-20`).
- Cleanup deletes rows only once `expires_at` is older than the 24-hour retention window —
  consumed and unconsumed alike — as one transactional unit. The session cleanup in the same
  round runs after this segment and skips sessions still referenced by retained code rows.

The authoritative semantics are `PS-05` and its related rows in
[CanonicalSemanticModel.md](../../oidc/CanonicalSemanticModel.md); this page is a projection, not a
second rule set.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
