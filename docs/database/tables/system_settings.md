# system_settings (removed)

`system_settings` was SignaCore's legacy per-key global configuration table. It was replaced by
the shared ServiceMantle `service_settings` aggregate — first as the runtime authority
(ServiceMantle issue #548), and finally as the only stored configuration: the `RetireSystemSettings`
migration of both providers **drops the table under a guard**, and the legacy store, snapshot,
migration, and configuration protector types were removed with it (ServiceMantle issue #556).

Historical notes, kept for operators reading older databases:

- The table held one row per setting keyed by the ASP.NET Core colon-separated name (for example
  `Endpoints:PublicBaseUrl`), with `value` (plaintext, canonical JSON, or an encrypted envelope when
  `is_secret` was set), `value_type`, `is_secret`, `version`, `updated_at`, and `updated_by`.
- Secret rows held an AES-GCM envelope keyed from the external root key with the setting key bound
  as authenticated associated data — a data class separate from the shared sensitive-value envelope
  of `service_settings` (HKDF domain, AAD, and purpose all differ).
- The runtime-switch era (a build that includes commit `e45e9741`) migrated these rows once into
  the shared aggregate on startup and left them untouched afterwards. That migration no longer
  exists; the rows themselves were never rewritten by the switch.

The runtime authority, its invariants, and its ownership rules are documented in
[service_settings](./service_settings.md), and the upgrade procedure for deployments that still
hold legacy rows is documented in [System settings retirement](./system-settings-retirement.md).
