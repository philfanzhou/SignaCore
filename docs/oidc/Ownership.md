# Ownership: ServiceMantle and SignaCore

**Status: target design.** See [README](./README.md).

[ServiceMantle](https://github.com/philfanzhou/ServiceMantle) supplies shared service
infrastructure. SignaCore owns identity and the OAuth/OIDC protocol. The split matters here because
several capabilities this design needs — a cross-instance Data Protection key ring, log scrubbing,
metrics — could plausibly be built in either place, and building them twice is the failure mode.

**The rule: no implementation task under this epic builds a second copy of anything in the
ServiceMantle column.** If a needed piece is missing there, the task blocks on a ServiceMantle issue
rather than growing a local implementation.

## The split

| Capability | ServiceMantle | SignaCore |
| --- | --- | --- |
| Data Protection key storage and cross-instance key ring | ServiceMantle#40, #41 — storage, rotation, sharing | The identity cookie scheme, its distinct purpose string, and isolation from `qz_admin_session` |
| Structured-log scrubbing | ServiceMantle#83 — the pipeline | The field names in [Security](./Security.md#values-that-must-never-be-written-down) |
| Serilog host configuration | ServiceMantle#84 | Product event names and their properties |
| OpenTelemetry | ServiceMantle#86 — tracing host and exporters | Spans for authorize, redeem, userinfo, logout, and their attributes |
| Prometheus | ServiceMantle#88 — exporter and host wiring | The `signacore_oidc_*` metrics and their labels |
| Sensitive header handling | ServiceMantle#142 | Which headers are sensitive for OIDC: `Authorization`, `Cookie`, `Set-Cookie` |
| Dual-instance PostgreSQL acceptance base | ServiceMantle#155 — the harness | The OIDC scenarios run on it: cross-instance code redemption and session revocation |
| Rate limiting | ServiceMantle#92 — single-instance setup and management limiting only | Every partition in [Security](./Security.md#rate-limits-collected), and cross-instance limiting if a deployment needs it |
| OAuth/OIDC protocol, JWT, refresh tokens, accounts, applications, callbacks, signing keys, JWKS, discovery | — | All of it, per the ServiceMantle#25 / #105 boundary |

ServiceMantle#92 is called out because its scope is easy to over-read. It covers the setup and management
endpoints on a single instance. It does not cover OIDC client or account partitions, and it does not
provide cross-instance shared state. Those stay here.

## What SignaCore never builds

- A second Data Protection key store or key-ring implementation.
- A second log-scrubbing pipeline, Serilog bootstrapper, OpenTelemetry host, or Prometheus exporter.
- A second sensitive-header list mechanism.
- A second dual-instance test harness.

## What ServiceMantle never sees

- Account, application, session, token, or credential data.
- Protocol decisions: error codes, claim names, lifetimes, comparison rules.
- The `system_settings` contents, which are SignaCore's configuration authority.

## Blocking

An implementation task whose ServiceMantle prerequisite has not shipped records that as a GitHub
native `blocked by` edge and does not proceed with a local substitute. "We will replace it later"
does not survive contact with a release: the substitute becomes the implementation, and then there
are two.

If a prerequisite turns out to be missing entirely, the correct action is to open a ServiceMantle
issue and link it, not to widen this epic's scope.
