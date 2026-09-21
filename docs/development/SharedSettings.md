# Shared settings stack

SignaCore registers its product configuration on the shared ServiceMantle setting contract. Since
the runtime switch, this stack is the configuration authority: the bootstrap phase activates the
shared snapshot, `IConfiguration` is fed through the reverse projection onto the legacy colon
keys, first-run setup writes the shared aggregate, the admin console's settings page reads and
writes the shared aggregate through the shared management endpoints, and the protected legacy
configuration import writes the aggregate's first version directly, without ever writing the
legacy `system_settings` table. That table stays as read-only legacy data.

> Status: implemented (ServiceMantle tasks #101 and #547, runtime switch #548, admin console
> switch #145, import switch #146; the legacy `SettingsSnapshotValidator` was retired by
> ServiceMantle task #555). Removing the remaining old types is tracked after those.

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
`Program.cs` after the identity infrastructure. The PendingSetup host registers only the
transactional update path (`AddSignaCoreSharedSettingUpdates`) so first-run completion writes the
aggregate; nothing that reads or publishes a runtime snapshot is composed before one can exist.

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

Everything else lives exactly once, in the shared stack: value types, the "must be present"
requirement for keys with real defaults, `requiresRestart` (all keys), the integer semantics of
every Number key, the three numeric ranges, the fixed JSON root kinds, and every cross-key rule
(base URL normalization, HTTPS policy, issuer equality, non-blank keys, SMS/LDAP/WeChat binder
validation, reverse-proxy IP parsing) in `SignaCoreSettingCompositeValidator`. The retired legacy
snapshot validator left behind two input-form duties, now carried by a thin adapter instead of a
second rule set:

- `SettingCandidateValidation` (entry: `SharedSettingComposition.ValidateCompleteCandidate`) is
  the pre-validation used by first-run setup, the legacy import, and the test installation
  fixtures. It checks that the complete legacy-keyed candidate carries every one of the 43 catalog
  keys — completeness precedes defaults, so a missing key is never silently filled in by the
  registry — and that every Number value is integer text (`IntegerSettingConstraint.IsIntegerText`,
  the legacy `NumberStyles.Integer` form), then maps through `SharedSettingKeys` onto the shared
  registry. All failures are closed, key-scoped codes.
- `PublicBaseUrlNormalizer` holds the URL normalization helper (`TryNormalizeBaseUrl`) used by the
  composite validator, the setup pre-check, and the legacy import's plain-HTTP compatibility
  opt-in.

The accept/reject behavior is pinned by `SharedSettingContractTests`, a frozen matrix of fixed
inputs with pinned verdicts captured from the retired validator's baseline, and by the
`SettingCandidateValidationTests` and `PublicBaseUrlNormalizerTests` matrices.

## Runtime activation (#548)

- During the bootstrap phase, inside the startup initialization lock, a database whose aggregate is
  still empty while legacy `system_settings` rows exist runs the one-shot migration (#547): every
  legacy row is decrypted with the legacy protector and re-protected into the shared aggregate as
  its first version, inside one caller-owned transaction. A migration refusal fails startup with
  key names and a classification code only; the installation is never rolled back to `Pending`.
- The bootstrap phase then activates the snapshot with a bootstrap-owned
  `ServiceSettingSnapshotLoader` and publishes it on one `ServiceSettingCurrentSnapshotAccessor`
  instance, which is pre-registered with DI so the composed snapshot services observe the same
  process-local snapshot instead of building a second, empty one.
- The activated snapshot is projected back onto the legacy colon-keyed configuration shape
  (`SharedSettingConfigurationProjection`): every normalized key maps through
  `SharedSettingKeys`, JSON values expand into `IConfiguration` sub-keys exactly like the legacy
  snapshot path, and no consumer of `IConfiguration` had to change. Equivalence against the legacy
  path is asserted key by key, including the JSON sub-keys.
- The configuration-version authority is the aggregate version (a `long`, narrowed once at the
  bootstrap boundary). **The version is renumbered by the migration**: a deployment that just
  migrated reports version 1 again, regardless of what the legacy `MAX(version)` used to be. The
  guarantee is that the version is monotonic from there and that every instance observing the same
  persisted state observes the same version and the same complete snapshot.
- Fail-closed discipline is unchanged in shape: an incomplete, damaged, or undecryptable aggregate
  refuses activation without replacing an existing snapshot, reports key names and closed
  classification codes only, and never rolls a `Completed` installation back to `Pending`.

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
- First-run setup writes the shared aggregate through the same update service as the first version
  of the completion transaction, together with the administrator, the installation audit
  projection, and the code consumption. The admin console reaches the aggregate through the
  shared management endpoints, and the protected legacy configuration import writes the same
  aggregate the same way (both below). The legacy `system_settings` table is no longer written
  by the runtime; it is read-only legacy data.

## Admin console endpoints (#145)

- The normal host maps the shared management API v1 group with
  `MapServiceMantleSettingQueries()` (definitions + current values) and
  `MapServiceMantleSettingUpdates(ManagementSettingUpdateExecutor.ExecuteAsync)`. The Bootstrap
  and Setup hosts never map the group, so those phases expose no settings surface. The legacy
  `AdminSettingsController` and its models are gone; `/api/admin/settings` no longer exists.
- The update executor resolves a fresh scope and its own `IdentityDbContext` built with
  `UseIdentityDatabase(options, enableRetryOnFailure: false)`, opens one serializable transaction,
  runs the shared update service, and returns Applied only after the commit completed. The
  scoped update service is deliberately not resolved there: it is bound to the host's retrying
  business context, and a caller-opened transaction under a retrying strategy is exactly what the
  shared contract forbids. One attempt, no replay.
- The current-values response carries the product header
  `X-SignaCore-Running-Configuration-Version`: the version this process activated at bootstrap
  (`InstallationRuntimeState.ConfigurationVersion`), added by a local middleware on exactly that
  successful GET. The shared JSON stays untouched, the header appears on no other endpoint, and a
  cross-origin console reads it through the AdminWeb CORS `WithExposedHeaders` entry. The console
  derives restart-pending from the header versus the response version; a missing or unparseable
  header renders "running version unknown" and never infers activation. A server version beyond
  the JavaScript safe-integer range is treated as inexpressible: the console refuses to submit
  rather than send a rounded `expectedVersion`.

## Protected legacy configuration import (#146)

- A pre-change deployment — business data present, no stored configuration of either era — is
  upgraded inside the startup initialization lock: the deployment's effective `IConfiguration`
  (appsettings, environment variables, launcher injection) is read once by
  `LegacyConfigurationInput`, the thin product input adapter that owns the historical reading
  rules (catalog defaults, trimming, the `AdminBootstrap:Username` alias with canonical-key
  precedence, JSON section/scalar shapes, the plain-HTTP compatibility opt-in, and the
  required-key completeness check with key names only).
- The complete candidate is mapped through `SharedSettingKeys` and written with one
  `ServiceSettingUpdateCommand(expectedVersion: 0, full batch, legacy-import operator)` inside one
  caller-owned serializable transaction, followed by the completed installation row it requires
  and the value-free product audit `installation.legacy_import.completed` (event, key count,
  version). The shared update service owns validation and re-protection; nothing is persisted
  while reading. The legacy `system_settings` table is never written by the import.
- PostgreSQL's retrying execution strategy wraps the attempt: every attempt re-begins its own
  transaction from a cleared change tracker and re-reads the authority, so no tracked entity or
  audit row survives into a retried attempt.
- A version conflict is never treated as this run's success: the committed aggregate is re-read,
  and the shared loader further down the startup path fully validates it; a restart after a
  committed import is an idempotent re-run that writes no second import or per-key audit. Failure
  rolls the whole attempt back — no partial aggregate, no installation row, no audit — and fails
  startup with key names and classification codes only, never re-opening anonymous setup.

## Operators

- The shared aggregate is the configuration authority. Changes land through the shared update path
  and take effect on the next restart (all keys are `requiresRestart`); the admin console edits
  the shared aggregate directly, with the version it loaded as `expectedVersion` and a fixed 409
  conflict answer when another session moved ahead.
- The PostgreSQL concurrency contract (exactly one winner per version) runs in CI under
  `RUN_SIGNACORE_DATABASE_CONTRACTS=true`; the SQLite contract tests run in every build.
