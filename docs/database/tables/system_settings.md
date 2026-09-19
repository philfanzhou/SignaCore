# system_settings

Legacy global application configuration. Since the runtime switch, the authoritative configuration
lives in the shared `service_settings` aggregate (see `service_settings.md` and
[Shared settings stack](../../development/SharedSettings.md)); this table is read-only legacy data,
still served by the legacy admin endpoints and the one-shot migration source until their own
switches land. Deployments that predate the aggregate keep their rows untouched here.

## Columns

- key (string, primary key) — ASP.NET Core configuration name, for example `Endpoints:PublicBaseUrl`
- value (text, not null) — invariant string for scalars, canonical JSON for structured values, or an
  encrypted envelope when `is_secret` is true
- value_type (string, not null) — `String`, `Number`, `Boolean`, or `Json`
- is_secret (boolean, not null)
- version (integer, not null) — the `configuration_version` this row was written under
- updated_at (timestamp, not null)
- updated_by (string, nullable)

## Relationships and invariants

- Settings are read, validated, and activated as one snapshot. A partially valid configuration never
  becomes the running configuration.
- Which keys belong here is defined by the settings catalog in versioned application code, together
  with their safe product defaults. Only the canonical public base URL and the issuer derived from it
  have no default; first-run setup supplies them.
- `Json` values are expanded into ordinary configuration keys on load, so a structured setting binds
  exactly like the appsettings.json section it replaced.
- Secret rows hold an AES-GCM envelope keyed from the external root key, with the setting key and
  schema version bound as authenticated associated data. Secret values are never returned from
  general settings-list APIs, and deleting or replacing a row does not reveal the previous value.
- The database connection string is deliberately absent: it cannot be stored in the database it is
  needed to open. It lives in the writable protected bootstrap file.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct
database access. Editing rows by hand bypasses snapshot validation and encryption. The runtime no
longer reads this table for its active configuration; the startup migration reads it exactly once
per not-yet-migrated deployment.
