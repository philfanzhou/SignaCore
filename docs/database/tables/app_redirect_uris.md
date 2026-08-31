# app_redirect_uris

Canonical browser redirect registrations owned by an application. These values are independent of
the application's server-to-server claims callback.

## Columns

- id (UUID, primary key)
- app_registration_id (foreign key to `app_registrations.id`)
- kind (`Redirect` or `PostLogout` enum value)
- canonical_uri (1–501 ASCII characters; registration input is limited to 500 characters, and
  empty-path canonicalization can add one `/`)

## Relationships and invariants

- The unique index on `(app_registration_id, kind, canonical_uri)` prevents duplicate canonical
  values within either redirect kind while allowing the same value in both kinds.
- Deleting the owning application cascades to all of its redirect registrations.
- Each kind contains at most ten values. Domain validation enforces this limit before persistence.
- Registration stores the canonical form produced by the interactive OIDC URI validator. Protocol
  requests compare their unmodified input to `canonical_uri` with ordinal equality.
- URI query strings are permitted and can contain sensitive values. Logs and validation errors do
  not include the registered URI.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct
database access.
