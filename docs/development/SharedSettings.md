# Shared settings stack

SignaCore registers its product configuration on the shared ServiceMantle setting contract, in
parallel to the legacy `system_settings` path. This stack is composed only in the normal host;
Setup Mode and Bootstrap Configuration Mode deliberately keep their existing composition.

> Status: implemented (ServiceMantle task #101). The legacy path stays fully operational; the
> switch, the data import, and the removal of the old path are tracked separately.

## What is registered

| Capability | Registration |
| --- | --- |
| Product definitions (43 keys) | `ServiceSettingDefinitions : IServiceSettingDefinitionProvider` |
| Cross-key rules | `SignaCoreSettingCompositeValidator : IServiceSettingCompositeValidator` |
| Integer Number semantics | `IntegerSettingConstraint : IServiceSettingValueConstraint` |
| Store (single aggregate per service) | `EfCoreServiceSettingStore<IdentityDbContext>` over `IDbContextFactory<IdentityDbContext>` |
| Transactional updates + audits | `EfCoreServiceSettingUpdateTransaction<IdentityDbContext>` + `ServiceSettingUpdateService` (scoped) |
| Sensitive-value root key | `MasterKeyRootKeySource : IServiceSettingRootKeySource` (Base64 of the bootstrap master key) |
| Query / snapshot services | `AddServiceMantleSettingSnapshots()` |

Everything lives in `src/SignaCore.Host/Configuration/` and is internal; no public API is added.
The composition entry point is `ServiceMantleComposition.AddSignaCoreSharedSettings`, called from
`Program.cs` after the identity infrastructure.

## Key mapping

Every legacy database-backed key maps to exactly one normalized key: `:` becomes `.`, and
PascalCase segments become snake_case, for example `Endpoints:PublicBaseUrl` →
`endpoints.public_base_url`, `Consul:Discovery:PreferIPAddress` →
`consul.discovery.prefer_ip_address`. The full pinned table lives in `SharedSettingKeys.cs` and is
asserted entry by entry against `SystemSettingsCatalog` in
`SharedSettingDefinitionMappingTests`.

## Declared differences from the legacy catalog

- Sensitive definitions (`sms.otp_hmac_key`, `sms.bypass_code`, `sms.profiles`,
  `wechat.app_secret`, `ldap.directories`, `consul.token`) carry no default value and are not
  required: **missing means unset**. The composite validator evaluates them exactly as the legacy
  validator evaluated their empty defaults.
- Legacy empty-string and empty-document defaults (`""`, `[]`, `{}`) are not migrated. Those keys
  are optional and start unset; the composite validator and the runtime binders treat them like
  the legacy empty value.
- Until the aggregate is seeded by its first update, the current-values query fails closed with
  the shared closed error classification: the two setup-collected keys
  (`endpoints.public_base_url`, `jwt.issuer`) are required and have no defaults.

Everything else is equivalent: value types, the "must be present" requirement for keys with real
defaults, `requiresRestart` (all keys), the legacy integer semantics of every Number key, the
three numeric ranges, the fixed JSON root kinds, and every cross-key rule of
`SettingsSnapshotValidator` (base URL normalization, HTTPS policy, issuer equality, non-blank
keys, SMS/LDAP/WeChat binder validation, reverse-proxy IP parsing). Equivalence is pinned by
`SharedSettingEquivalenceTests`, which feeds equivalent snapshots to both validators and requires
identical accept/reject outcomes.

## Storage and updates

- `service_settings` holds one row per service (`signacore`), with the complete value set as JSON
  and `version` as the concurrency token (`version > 0` check constraint). The aggregate starts
  empty at version 0; the first update creates version 1.
- Sensitive values are stored as `sm:v1:` envelopes (HKDF-SHA-256 + AES-256-GCM, bound to the
  service id and the setting key) under the external root key. Plaintext never reaches the table.
- Updates flow through `ServiceSettingUpdateService` inside a caller-owned transaction and
  savepoint; each changed key writes exactly one `configuration.changed` audit row into
  `service_audit_logs` in the same savepoint. Validation, protection, storage, transaction, and
  context failures produce the closed result set (`ValidationFailed`, `ProtectionFailed`,
  `StorageFailed`, `VersionConflict`, `TransactionRequired`, `ContextNotClean`) and leave zero
  changes and zero audit rows.
- The legacy `system_settings` table, the legacy endpoints, and the first-run setup write path are
  untouched; no data is imported or double-written (tracked separately).

## Operators

- The new aggregate is a parallel source of truth until the switch: changing settings through the
  legacy admin console does not update `service_settings`, and updating `service_settings` does
  not change the running configuration (all `requiresRestart` keys).
- The PostgreSQL concurrency contract (exactly one winner per version) runs in CI under
  `RUN_SIGNACORE_DATABASE_CONTRACTS=true`; the SQLite contract tests run in every build.
