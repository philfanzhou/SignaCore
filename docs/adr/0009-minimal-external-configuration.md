# Minimal External Configuration

- Status: Accepted
- Date: 2026-10-17
- Decision owners: SignaCore maintainers
- Extends: [ADR 0002](./0002-database-backed-configuration.md), [ADR 0008](./0008-transport-security-is-a-deployment-decision.md)
- Scope decision record: [#599](https://github.com/philfanzhou/SignaCore/issues/599)

## Context

ADR 0002 moved global application configuration into the business database behind a writable
bootstrap file, and the configuration-cleanup series ([#594](https://github.com/philfanzhou/SignaCore/issues/594),
[#595](https://github.com/philfanzhou/SignaCore/issues/595),
[#596](https://github.com/philfanzhou/SignaCore/issues/596),
[#597](https://github.com/philfanzhou/SignaCore/issues/597)) has since converged the catalog:
managed keys own their whole domain, dead and retired keys are gone from the definition table,
and the launcher carries no application settings. That work repeatedly faced the same question —
when a value exists both outside and inside the database, which one wins, and what does the
process do about the loser? The implementations answered consistently; this record fixes that
answer as the product's configuration boundary so later changes stop re-litigating it.

## Decision

The external configuration — what a deployment must or may supply outside the business database —
is the smallest set that can open and expose the service:

1. **The bootstrap file** (`config/signacore.bootstrap.json`): the database provider, server
   version, and connection string, plus the inline external root key. These cannot live in the
   database they open and decrypt (ADR 0002).
2. **The three first-install facts** collected by the protected `/setup` flow: the canonical
   public base URL (from which the issuer is derived) and the initial administrator username and
   password. Everything else a new installation needs ships as a safe product default.
3. **The listening HTTP port** (`Endpoints:Http`, default `5002`, overridable as
   `Endpoints__Http`). It names the process's own listener, so it stays per-instance process
   configuration.

Everything else is a managed `service_settings` key. Two rules govern the boundary:

- **Per-instance environment variables act only as overrides, never as configuration.** A process
  key that duplicates a managed key exists to let one instance diverge from the shared snapshot
  (the multi-instance Consul advertisement through `ServiceDiscovery:Address` / `ServiceDiscovery:Port` /
  `ServiceDiscovery:HealthScheme` over the `consul.discovery.*` defaults,
  [#594](https://github.com/philfanzhou/SignaCore/issues/594)) or to configure a stage that runs
  before a snapshot exists (the launcher `APP_TITLE`, which labels only the bootstrap and setup
  pages; the managed `app.title` titles the running console,
  [#595](https://github.com/philfanzhou/SignaCore/issues/595)). Where the database also owns the
  value, the activated snapshot is layered last and wins.
- **External leftovers warn, never fail.** A deployment that still supplies a managed key from
  appsettings, environment variables, or the command line — including flat-named transitional
  variables such as `SMS_BYPASS_CODE` ([#596](https://github.com/philfanzhou/SignaCore/issues/596))
  — gets one startup warning per key or variable name, never a refused start and never a logged
  value. The warning exists so an operator editing the external copy stops expecting an effect.

Four confirmed decisions follow from this boundary and are recorded here as settled:

- **Consul advertisement** ([#594](https://github.com/philfanzhou/SignaCore/issues/594)): the
  advertised address, port, and health scheme default from the managed
  `consul.discovery.ip_address`, `consul.discovery.port`, and `consul.discovery.health_scheme`
  keys; the process keys above remain key-by-key per-instance overrides. The dead
  `consul.discovery.prefer_ip_address` switch is retired.
- **SPA title** ([#595](https://github.com/philfanzhou/SignaCore/issues/595)): the admin console
  title is the managed `app.title` setting (default `SignaCore`, non-blank validated); the
  launcher variable is inert on the normal host and is reported as a legacy override.
- **Warn-only external leftovers** ([#596](https://github.com/philfanzhou/SignaCore/issues/596)):
  transitional flat-named variables lose their silent fallbacks and gain explicit per-name
  warnings, keeping the policy uniform with every other managed key.
- **Development credential files stay out of the repository**
  ([#598](https://github.com/philfanzhou/SignaCore/issues/598)): local credential files are
  untracked and ignored; only tracked examples with placeholder values are committed.

## Consequences

- The external surface is enumerable: the bootstrap file, the three setup facts, the listening
  port, and the documented per-instance overrides. An operator can audit launcher drift by
  comparing it against that list; anything else that still appears in it is a warned leftover.
- The definition table in `ServiceSettingDefinitions` is the authoritative managed catalog; the
  key counts in the configuration documentation must track it exactly.
- A misconfigured external leftover is visible but non-fatal: the service starts, the database
  wins, and the warning names only the key or variable. Removing the leftover is the operator's
  follow-up, not a startup prerequisite.
- Retired keys extend the same tolerance to stored rows: reads drop them, updates naming them are
  the generic unknown-key rejection, and dropping the rows is optional housekeeping.
- This record changes no code, schema, or migration; a rollback of any implementing change
  follows that change's own notes. The boundary itself is enforced by the existing snapshot
  layering, `LegacyConfigurationGuard` warnings, and the guarded bootstrap file.
