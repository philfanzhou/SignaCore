# Interactive OIDC Ownership

**Status: target ownership contract.** Protocol behavior remains normative only in the
[canonical semantic model](./CanonicalSemanticModel.md). This document assigns implementation and
operational responsibility; it does not activate a capability.

## Product boundary

| Concern | Owner | Contract source and design task |
| --- | --- | --- |
| Accounts, credentials, client policy, redirect registrations, identity sessions, authorization requests/codes, refresh families, signing keys, audit records, and protocol cleanup | SignaCore | [PS-01..23](./CanonicalSemanticModel.md#artifact--persistence-relationship), [#130](https://github.com/philfanzhou/SignaCore/issues/130), [#131](https://github.com/philfanzhou/SignaCore/issues/131), [#132](https://github.com/philfanzhou/SignaCore/issues/132), [#133](https://github.com/philfanzhou/SignaCore/issues/133) |
| Authorization, login, token, UserInfo, and prepared-logout wire contracts | SignaCore | [IN-01..36](./CanonicalSemanticModel.md#endpoint--external-input), [#130](https://github.com/philfanzhou/SignaCore/issues/130), [#131](https://github.com/philfanzhou/SignaCore/issues/131), [#132](https://github.com/philfanzhou/SignaCore/issues/132) |
| OIDC-specific rate partitions, protocol audit semantics, low-cardinality product metrics, sensitive-value canaries, and the production gate | SignaCore #71 | [DF-01..15](./CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow), [AC-13](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#129](https://github.com/philfanzhou/SignaCore/issues/129), [#134](https://github.com/philfanzhou/SignaCore/issues/134), [security contract](./Security.md) |
| Generic structured logging, tracing, metrics export, sensitive-header registration, and host integration components that SignaCore explicitly adopts | ServiceMantle, consumed by SignaCore | [AC-13](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#129](https://github.com/philfanzhou/SignaCore/issues/129), [#134](https://github.com/philfanzhou/SignaCore/issues/134) |
| BFF state/nonce/verifier generation and binding, ID-token validation, server-side token storage, and local administrative authorization | Each confidential BFF | [caller responsibilities](./CanonicalSemanticModel.md#guarantees-and-caller-responsibilities), [#130](https://github.com/philfanzhou/SignaCore/issues/130) |
| Access-token signature, issuer, audience, time, and required-claim validation | Each downstream resource service | [DF-07](./CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow), [caller responsibilities](./CanonicalSemanticModel.md#guarantees-and-caller-responsibilities), [#131](https://github.com/philfanzhou/SignaCore/issues/131) |

No downstream system writes SignaCore tables or references SignaCore assemblies. Stable integration
surfaces are HTTP Discovery, JWKS, protocol endpoints, and signed claims. Local roles and permissions
belong to the consuming service and are keyed by issuer plus subject, not by a copied password.

## ServiceMantle integration boundary

ServiceMantle remains a generic host library, not the owner of SignaCore protocol decisions. The
current native dependency for SignaCore #71 names ServiceMantle
[#83](https://github.com/philfanzhou/ServiceMantle/issues/83),
[#84](https://github.com/philfanzhou/ServiceMantle/issues/84),
[#86](https://github.com/philfanzhou/ServiceMantle/issues/86),
[#88](https://github.com/philfanzhou/ServiceMantle/issues/88), and
[#142](https://github.com/philfanzhou/ServiceMantle/issues/142). Closed dependencies may be consumed;
open dependencies are not described as shipped.

ServiceMantle [#92](https://github.com/philfanzhou/ServiceMantle/issues/92) is a setup/management
single-instance rate-policy task. It is not a distributed OIDC limiter and does not discharge
SignaCore #71. ServiceMantle [#155](https://github.com/philfanzhou/ServiceMantle/issues/155) is a
multi-instance SignaCore acceptance task, not a reusable test harness.

SignaCore currently owns working local host composition, database-backed Data Protection keys,
logging, telemetry, metrics export, redaction, and rate limiting. The open ServiceMantle integration
epic [#25](https://github.com/philfanzhou/ServiceMantle/issues/25) may replace generic plumbing only
after behavior is characterized and adopted through an explicit SignaCore task. This design neither
duplicates a generic component already adopted nor deletes current behavior in anticipation of an
open dependency.

## Configuration and deployment ownership

OIDC business policy follows the repository-wide configuration boundary: global policy belongs in
`system_settings`; provider/version/connection string and the external root key remain deployment
bootstrap concerns. PostgreSQL owns multi-instance transactional guarantees. SQLite owns the same
semantic results for one SignaCore instance and one writer, as fixed by
[PS-22](./CanonicalSemanticModel.md#artifact--persistence-relationship) and
[#133](https://github.com/philfanzhou/SignaCore/issues/133).

Operators own TLS termination, a stable public issuer/origin, root-key distribution, database
availability, and monitoring. They must not enable an advertised capability while any activation
prerequisite or the operational gate is incomplete.
