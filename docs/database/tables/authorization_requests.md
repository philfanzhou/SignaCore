# authorization_requests

Shared server-side authorization requests (login continuations). A browser leaves
`GET /oauth2/authorize` with a one-time `login_handle` and later returns to the validated request
through its digest, on any instance, using only the shared database.

## Columns

- id (UUID, primary key; public record id, safe in diagnostics)
- handle_digest (versioned SHA-256 digest, unique index; the plaintext 43-character `login_handle`
  is returned exactly once at creation and never persisted)
- app_registration_id
- redirect_uri (snapshot of the exact registered canonical redirect URI value, not a foreign key)
- scope (canonical space-delimited scope snapshot)
- state / nonce (byte-for-byte snapshots)
- code_challenge (S256 challenge snapshot; the PKCE verifier is never stored)
- created_at / expires_at / consumed_at (nullable)

## Relationships and invariants

- app_registration_id is a non-null restrictive reference to app_registrations. Deleting an
  application while continuation rows exist fails; nothing cascades into or out of this table.
- The redirect URI is a value snapshot: removing the registration does not reshape a stored row
  during its lifetime. Current client, redirect, scope, and account policy are revalidated by the
  orchestrating flow before any redirect; a stored row is never itself an authorization.
- A row is available only while `consumed_at IS NULL` and `expires_at` lies in the future; the
  handle lifetime is 10 minutes. Expiry never writes `consumed_at`, and consumption is not
  revocation.
- Consumption is one atomic conditional update, so at most one concurrent consumer commits. Inside a
  caller-owned transaction it commits or rolls back with the surrounding success transaction; a
  committed consumption stays authoritative.
- A missing, expired, or consumed digest resolves to a single "unavailable" result with no state
  write and no replay audit.
- Cleanup deletes rows only after they are expired and beyond the 24-hour retention window, as one
  transactional unit; no reference is ever nulled to enable a delete, and no table references this
  one.

The authoritative semantics are `PS-03` and its related invariants in
[CanonicalSemanticModel.md](../../oidc/CanonicalSemanticModel.md); this page is a projection, not a
second rule set.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
