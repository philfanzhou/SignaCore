# service_settings

The shared ServiceMantle settings aggregate — the authoritative global application configuration
since the runtime switch. One row per service (`signacore`); the business database is the
configuration authority, so every instance reads the same active configuration and there is no
per-instance drift. See [Shared settings stack](../../development/SharedSettings.md).

## Columns

- service_id (string, primary key) — `signacore`
- values_json (text, not null) — the complete value set as one JSON object keyed by normalized
  setting keys (`endpoints.public_base_url`), with sensitive values as `sm:v1:` envelopes
- version (integer, not null, check `version > 0`) — the aggregate version, concurrency token and
  configuration version in one
- updated_at_utc (timestamp, not null)
- updated_by (string, not null)
- restart_required (boolean, not null)

## Relationships and invariants

- The aggregate is loaded, validated, and activated as one complete snapshot; a partially valid
  configuration never becomes the running configuration, and an incomplete, damaged, or
  undecryptable aggregate fails startup closed without replacing an existing snapshot.
- Version numbering restarts at 1 when a legacy deployment is migrated: the version is monotonic
  from there and identical across instances observing the same persisted state, but it is not
  aligned with the legacy `system_settings` `MAX(version)`.
- Secret values are `sm:v1:` envelopes (HKDF-SHA-256 + AES-256-GCM) bound to the service id and the
  normalized setting key under the external root key. Plaintext never reaches the table, and secret
  values are never returned from general settings-list APIs.
- Every update writes exactly one `configuration.changed` audit row per changed key into
  `service_audit_logs`, in the same transaction and savepoint as the value change.

## Ownership

SignaCore owns this row through the shared transactional update path. Other services must use the
HTTP API rather than direct database access. Editing the row by hand bypasses snapshot validation
and encryption.
