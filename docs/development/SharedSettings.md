# Shared settings stack

SignaCore registers its product configuration on the shared ServiceMantle setting contract. Since
the runtime switch, this stack is the configuration authority: the bootstrap phase activates the
shared snapshot, `IConfiguration` is fed through the reverse projection onto the legacy colon
keys, first-run setup writes the shared aggregate, the admin console's settings page reads and
writes the shared aggregate through the shared management endpoints, and the protected legacy
configuration import writes the aggregate's first version directly. The legacy
`system_settings` table — together with its store, snapshot, one-shot migration, and legacy
configuration protector — was removed by the guarded `RetireSystemSettings` drop (ServiceMantle
issue #556); see [System settings retirement](../database/system-settings-retirement.md).

> Status: implemented (ServiceMantle tasks #101 and #547, runtime switch #548, admin console
> switch #145, import switch #146; the legacy `SettingsSnapshotValidator` was retired by
> ServiceMantle task #555, and the legacy storage was retired by task #556).

## What is registered

| Capability | Registration |
| --- | --- |
| Runtime definitions (45 unique keys) | `ServiceSettingDefinitions` plus shared `GrafanaLokiSettingDefinitions` and `OtlpSettingDefinitions`; product `Table` retains legacy/UI metadata for every key |
| Cross-key rules | `SignaCoreSettingCompositeValidator : IServiceSettingCompositeValidator` |
| Integer Number semantics | `IntegerSettingConstraint : IServiceSettingValueConstraint` |
| Store (single aggregate per service) | `EfCoreServiceSettingStore<IdentityDbContext>` over `IDbContextFactory<IdentityDbContext>` |
| Transactional updates + audits | `EfCoreServiceSettingUpdateTransaction<IdentityDbContext>` + `ServiceSettingUpdateService` (scoped) |
| Sensitive-value root key | `MasterKeyRootKeySource : IServiceSettingRootKeySource` (Base64 of the bootstrap master key) |
| Query / snapshot services | `AddServiceMantleSettingSnapshots()` plus an isolated `ManagementSettingQuerySnapshot` for management observations |

Product definitions live in `src/SignaCore.Host/Configuration/` and management composition in
`src/SignaCore.Host/Management/`; both are internal and add no public API.
`SharedSettingComposition.CreateRegistry` explicitly selects the runtime definition providers and
product composite validator for both direct and DI composition. Startup, management queries, legacy import, and
bootstrap probing use the tolerant validator; setup and default updates add the product error-code
adapter over shared Loki endpoint/header and OTLP endpoint primitives. The automatic strict
validators contributed by `AddServiceMantleGrafanaLokiFromSettings` and
`AddOpenTelemetryOtlpExporterFromSettings` are not loaded into the product registry.

The composition entry point is `ServiceMantleComposition.AddSignaCoreSharedSettings`, called from
`Program.cs` after the identity infrastructure. The PendingSetup host registers only the
transactional update path (`AddSignaCoreSharedSettingUpdates`) so first-run completion writes the
aggregate; nothing that reads or publishes a runtime snapshot is composed before one can exist.

## Key mapping

Every legacy database-backed key maps to exactly one normalized key: `:` becomes `.`, and
PascalCase segments become snake_case, for example `Endpoints:PublicBaseUrl` →
`endpoints.public_base_url`, `Consul:Discovery:PreferIPAddress` →
`consul.discovery.prefer_ip_address`. The full pinned table lives in `SharedSettingKeys.cs` and is
asserted entry by entry against fixed expected values in
`SharedSettingDefinitionMappingTests`, together with the authoritative definition table in
`ServiceSettingDefinitions` (the legacy catalog it replaced was removed by ServiceMantle task
#143).

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
validation, reverse-proxy IP parsing) in `SignaCoreSettingCompositeValidator`. The Loki group rules
— the shared ServiceMantle combination evaluation over `loki.uri` (an absolute `http` or `https`
URL without user info, query, or fragment; the scheme is a deployment decision), `loki.authorization`
(set for the authenticated modes; absent when the explicit `loki.allow_no_authentication` opt-in is
selected, which also requires deleting any stored credential in the same batch) — and the OTLP
endpoint rules (absolute `http` or `https`, same structural shape), are strict for setup and
default updates; SignaCore translates the shared outcomes into its closed
`signacore.setting.*` codes instead of keeping a second state rule. Startup, management reads,
legacy import, and bootstrap probing accept older unusable optional telemetry values; the normal
host keeps the affected sink/exporter disabled with a fixed, value-free warning. Management
recovery applies the same optional rules with the narrowly scoped
baseline exception below. The retired legacy
snapshot validator left behind two input-form duties, now carried by a thin adapter instead of a
second rule set:

- `SettingCandidateValidation` (entry: `SharedSettingComposition.ValidateCompleteCandidate`) is
  the pre-validation used by first-run setup, the legacy import, and the test installation
  fixtures. It checks that the complete legacy-keyed candidate carries every one of the 46
  definition-table keys — completeness precedes defaults, so a missing key is never silently filled in by the
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

- The bootstrap phase activates the snapshot with a bootstrap-owned
  `ServiceSettingSnapshotLoader` and publishes it on one `ServiceSettingCurrentSnapshotAccessor`
  instance, pre-registered with DI as the runtime authority. Management queries refresh a separate
  accessor, so neither a read nor a persisted update replaces the process's activated snapshot.
- The activated snapshot is projected back onto the legacy colon-keyed configuration shape
  (`SharedSettingConfigurationProjection`): every normalized key maps through
  `SharedSettingKeys`, JSON values expand into `IConfiguration` sub-keys exactly like the legacy
  snapshot path, and no consumer of `IConfiguration` had to change. Equivalence against the legacy
  path is asserted key by key, including the JSON sub-keys.
- The configuration-version authority is the aggregate version (a `long`, narrowed once at the
  bootstrap boundary). The legacy-row migration renumbered a bridged deployment back to version 1
  regardless of the legacy `MAX(version)`; since the retirement there is no migration path at all —
  the aggregate is created by first-run setup or the protected import at version 1. The guarantee
  is that the version is monotonic from there and that every instance observing the same persisted
  state observes the same version and the same complete snapshot.
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
  aggregate the same way (both below). The legacy `system_settings` table no longer exists in
  the retired schema; nothing reads or writes it.

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

### Settings diagnostics (#530)

The normal host also maps a product read on the same protected group:
`GET /management/v1/settings/diagnostics`. It performs exactly one complete tolerant
materialization of the stored aggregate — the same isolated management loader the current-values
query uses, never the runtime authority — and answers, only when that load fully succeeds:

```json
{ "version": 4, "runningVersion": 3, "issues": [ { "key": "loki.uri", "errorCode": "signacore.setting.https_required" } ] }
```

`version` is the version the complete save was observed at, `runningVersion` is what this process
activated at bootstrap (the same fixed startup source as the response header), and `issues` names
the saved version's unusable optional telemetry rules as closed key + error-code pairs over the
registered keys (`loki.uri`, `loki.authorization`, `opentelemetry.otlp_endpoint`) and the three
fixed product codes (`signacore.setting.required`, `signacore.setting.https_required`,
`signacore.setting.runtime_invalid`). A healthy saved version answers `[]`. Issues describe the
saved version only — they make no claim about the running sink, network reachability, or sink
health. Any load, decrypt, or critical failure keeps the shared fixed
`503 {"errorCode":"management.settings.unavailable"}` with no partial or stale result, and no
endpoint, credential, exception, or arbitrary value is ever returned. The endpoint has no query
parameters — any query string is a fixed `400 management.request.invalid` — and no other HTTP
method is mapped. Caller cancellation propagates the request token instead of a success or error
classification. Older HTTP clients ignore the endpoint entirely.

The update endpoint's definite validation rejection (`ValidationFailed`, status 400) additionally
carries the product compatibility field, produced by a group-level endpoint filter that matches
exactly `POST /management/v1/settings` and reads only the safe metadata the consumer-owned executor
staged for that outcome:

```json
{ "errorCode": "management.request.invalid", "validationErrors": [ { "key": "loki.uri", "errorCode": "signacore.setting.https_required" } ] }
```

The top-level error code and status stay as they were, `validationErrors` is the shared closed
key + fixed-code list (a null key stays an explicit JSON null), and every other outcome is
untouched: parse rejections happen before the executor runs and stage nothing, so malformed or
unknown-key requests keep the generic 400 body; 409, 503, and 200 keep their existing shapes.
Nothing in either body reflects a secret, Authorization value, connection string, root key, raw
exception, or the complete values object.

## Legacy optional telemetry recovery

A protected settings GET loads and decrypts the complete stored snapshot with the same core rules
as startup, then uses ServiceMantle's safe projection (every sensitive value is null). Group filters
only shape the successful response; they never hide a failed complete load. This observation uses
an independent loader/accessor and cannot change running logging, telemetry, or login policy.
Unknown keys, bad types/constraints, invalid core configuration, unavailable root keys, and damaged
envelopes still fail closed with the existing fixed 503 response and no partial or stale values.

The management update executor captures its baseline from the shared update service's one load in
the existing serializable transaction. It does not pre-read, retry, or use another transaction.
Version conflict and exhaustion are checked before baseline materialization. All type, constraint,
identity, issuer, origin, account, and SMS/LDAP/WeChat/proxy rules still validate the complete
candidate. The only optional groups are Loki (`loki.uri`, `loki.authorization`,
`loki.allow_no_authentication`) and OTLP (`opentelemetry.otlp_endpoint`), evaluated
independently. An optional group can retain its older
unusable values only when the complete baseline successfully loaded/decrypted, the shared runtime
classifier says the baseline group is unusable, the command names no key in that group, and the
candidate group equals the baseline. The original stored values and protected envelopes remain
unchanged, and the group stays disabled at the next restart.

Naming any group key counts as touching the whole group, including case-equivalent names,
explicit unchanged values, and deletion — and touching the explicit opt-in switch
(`loki.allow_no_authentication`) selects the whole Loki group for the strict rules exactly like
the two legacy keys. Touched groups must satisfy the full strict rules; a new invalid group,
invalid ordinary/core setting, or null-key runtime validation error is never waived. Repair Loki
with an absolute HTTP(S) URL plus usable Authorization, or with the explicit no-authentication
opt-in and no stored credential; or explicitly delete the whole group in the same batch
(`value=null`). Partial repair/deletion that leaves the group unusable is rejected. Repair OTLP
with a valid HTTP(S) endpoint or delete its key. A valid repair or complete deletion of one group
can preserve the other untouched unusable group. Recovery itself never enables any authentication
mode implicitly: the opt-in defaults to `false` and changes only through an explicit management
update.

The admin console supports the whole recovery flow on the observability settings page: the
diagnostics panel shows the saved version's issues with fixed English explanations plus the
saved-versus-running version pair, and a failed diagnostics read is reported as unavailable —
never as "no issues". A diagnostics answer taken at a different saved version than the loaded
settings is shown as stale rather than as the current version's verdict. **Disable Loki** drafts
the atomic disable — the whole group (`loki.uri`, `loki.authorization`, and both explicit opt-in
switches) submitted as `null` in one save batch — and **Remove OTLP
endpoint** drafts the same for the single OTLP key; a normal empty sensitive input still means
"keep the current value" and never deletes. Removal drafts can be undone before saving, survive a
409 conflict or a validation rejection without retry, and clear only after the save committed.
A rejected save lists the per-key `validationErrors` with the same fixed English explanations.

Each successful update increments the aggregate version once and writes only the submitted keys'
audit rows. Failures and caller cancellation roll back the whole attempt. PostgreSQL serialization
conflicts in this caller-owned settings transaction use the existing 409 version-conflict result,
including conflicts at commit; unrelated provider errors remain fixed 503. There is no retry.
Reads and saves leave the running-version header and actual runtime settings unchanged; restart
the service to activate a repaired or disabled group.

The no-authentication opt-in key adds no schema change on either provider: it defaults to
`false`, and an older aggregate without it loads with `false`. Before rolling back to a release
that does not know the key, atomically delete it through this version's management interface (or
the whole Loki group) and restore a combination the older release supports — an older release may
refuse to start on unknown persisted keys. Keep the database and root key across the rollback.

The `loki.allow_insecure_http` key is retired (ServiceMantle 0.3.2): the shared loader fails
closed on persisted keys it has no definition for, so SignaCore's snapshot reads drop retired rows
before materialization (`RetiredSettingKeys`) — a leftover row never blocks startup, the
management query path, or a management update, and an update naming the retired key is the generic
unknown-key rejection. Operators may drop the stored row after upgrading; the drop is optional
housekeeping, not a migration requirement. See the upgrade notes in `Configuration.md`.

## Protected legacy configuration import (#146)

- A pre-change deployment — business data present, no stored configuration of either era — is
  upgraded inside the startup initialization lock: the deployment's effective `IConfiguration`
  (appsettings, environment variables, launcher injection) is read once by
  `LegacyConfigurationInput`, the thin product input adapter that owns the historical reading
  rules (catalog defaults, trimming, the `AdminBootstrap:Username` alias with canonical-key
  precedence, JSON section/scalar shapes, the plain-HTTP compatibility opt-in, and the
  required-key completeness check with key names only). This import is the configuration
  authority's only upgrade entry point since the legacy table was removed.
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

- The shared aggregate is the configuration authority — the only persisted configuration since
  the legacy table was retired. Changes land through the shared update path
  and take effect on the next restart (all keys are `requiresRestart`); the admin console edits
  the shared aggregate directly, with the version it loaded as `expectedVersion` and a fixed 409
  conflict answer when another session moved ahead.
- The PostgreSQL concurrency contract (exactly one winner per version) runs in CI under
  `RUN_SIGNACORE_DATABASE_CONTRACTS=true`; the SQLite contract tests run in every build.

## Retired transport keys

`security.hosted_login_http_test_origins` and `security.allow_non_https_issuer` are retired by
[ADR 0008](../adr/0008-transport-security-is-a-deployment-decision.md): plain-HTTP redirect URIs,
public base URLs, and issuers are accepted structurally in every environment, so the allowlist and
the opt-in had nothing left to gate. Both keys left the definition table and the legacy mapping.
The shared loader fails closed on persisted keys it has no definition for, so SignaCore's snapshot
reads drop retired rows before materialization (`RetiredSettingKeys`) — a leftover row never
blocks startup, the management query path, or a management update, and an update naming a retired
key is the generic unknown-key rejection. Operators may drop the stored rows with `value=null`
after upgrading; the drop is optional housekeeping, not a migration requirement. Before rolling
back to a binary that still knows one of the keys, delete the row first so the older release
accepts the aggregate.
