# app_exchange_trusts

Administered, directed trust edges that allow a refresh token issued to one application to be
exchanged for a session at another. See
[ADR 0003](../../adr/0003-cross-application-refresh-grant.md).

## Columns

- id (UUID, primary key)
- app_registration_id — the application that accepts the foreign refresh token
- source_app_registration_id — the application the refresh token was issued to
- approved_by (nullable administrator account id)
- created_at

## Relationships and invariants

- Both columns reference app_registrations and cascade on delete; an edge has no meaning without
  either endpoint.
- (app_registration_id, source_app_registration_id) is unique.
- A check constraint forbids self-trust: the two columns must differ.
- The row is directed. `A` accepting tokens from `B` says nothing about `B` accepting tokens from
  `A`; that requires a second row.
- The edge is ignored at validation time when the source application is inactive.
- Derived tokens may continue along directed edges. `A → B` and `B → C` permit A-to-B-to-C,
  with current account, application and admission checks at each hop; they do not authorize a
  direct A-to-C request. Removing B-to-C prevents the next exchange of a B-bound token.
- An empty table means the refresh-token application binding is enforced exactly as it was before
  this table existed, which is the default for every deployment.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
