# Interactive OIDC Security Contract

**Status: target security and release-gate contract. No runtime protection is activated by this
document.** The [canonical semantic model](./CanonicalSemanticModel.md) remains normative for every
state result, persisted relationship, external input, and sensitive-data boundary. SignaCore #71
owns implementation of the operational gate described here.

## Attack verification matrix

This matrix points to the controls and tests that must execute. It deliberately does not reproduce
the canonical event table.

| Attack or failure class | Required control and proof | Normative source | Closed design task |
| --- | --- | --- | --- |
| Open redirect, malicious client, or URI mutation | Establish a current registered client and exact URI before any redirect; revalidate both after continuation; never normalize a request URI | [IN-02, IN-03](./CanonicalSemanticModel.md#authorization-and-identity-login); [PS-20](./CanonicalSemanticModel.md#artifact--persistence-relationship); [SC-02..04](./CanonicalSemanticModel.md#end-to-end-semantic-scenarios) | [#130](https://github.com/philfanzhou/SignaCore/issues/130), [authorization](./AuthorizationEndpoint.md) |
| Parameter pollution or ambiguous decoding | Enforce one strict UTF-8 decode, cardinality before value access, fixed body limits, and endpoint-specific named fields | [endpoint input preamble and IN-01..36](./CanonicalSemanticModel.md#endpoint--external-input) | [#130](https://github.com/philfanzhou/SignaCore/issues/130), [#131](https://github.com/philfanzhou/SignaCore/issues/131), [#132](https://github.com/philfanzhou/SignaCore/issues/132) |
| Code interception or PKCE downgrade | Require the exact S256 shapes and constant-time verifier comparison; no optional or `plain` mode | [IN-07, IN-08, IN-24](./CanonicalSemanticModel.md#authorization-and-identity-login); [PS-21](./CanonicalSemanticModel.md#artifact--persistence-relationship) | [#130](https://github.com/philfanzhou/SignaCore/issues/130), [#131](https://github.com/philfanzhou/SignaCore/issues/131) |
| Code injection, misbinding, replay, or double redemption | Bind client, URI, session, scope, nonce, and challenge snapshots; lock session then code; commit exactly one issuance; execute replay only for committed consumption | [PS-03, PS-05](./CanonicalSemanticModel.md#artifact--persistence-relationship); [EV-20..28](./CanonicalSemanticModel.md#event--artifact--result); [SC-07..09, SC-13](./CanonicalSemanticModel.md#end-to-end-semantic-scenarios) | [#131](https://github.com/philfanzhou/SignaCore/issues/131), [code redemption](./TokenEndpoint.md) |
| Login CSRF, session fixation, credential oracle, or cookie crossover | Use isolated cookie/antiforgery purposes, new session ids, strict validation order, generic credential failure, and no management-cookie authority | [PS-18, PS-19](./CanonicalSemanticModel.md#artifact--persistence-relationship); [IN-10..15](./CanonicalSemanticModel.md#authorization-and-identity-login); [SC-19](./CanonicalSemanticModel.md#end-to-end-semantic-scenarios) | [#130](https://github.com/philfanzhou/SignaCore/issues/130), [identity login](./IdentityLogin.md) |
| Token substitution or confused consumer | Separate ID/access token types, audiences, claims, and validators; downstream services accept only access tokens for their own audience | [PS-12..15](./CanonicalSemanticModel.md#artifact--persistence-relationship); [DF-07, DF-08](./CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow) | [#131](https://github.com/philfanzhou/SignaCore/issues/131), [tokens](./Tokens.md) |
| UserInfo token-carrier abuse or stale authority | Accept one bounded Bearer header only and recheck token type, issuer, audience, client, account, session, and current claims | [IN-28, IN-29](./CanonicalSemanticModel.md#token-and-userinfo); [PS-16](./CanonicalSemanticModel.md#artifact--persistence-relationship); [EV-04, EV-05, EV-08, EV-09, EV-13, EV-15](./CanonicalSemanticModel.md#event--artifact--result) | [#132](https://github.com/philfanzhou/SignaCore/issues/132), [UserInfo](./UserInfo.md) |
| ID-token leakage during logout, forged redirect, or handle replay | Authenticate preparation, validate the hint server-to-server, store no token, expose only a digest-backed one-time handle, and keep standard logout metadata absent | [IN-30..36](./CanonicalSemanticModel.md#logout-without-an-id-token-in-the-browser); [DF-08, DF-10](./CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow); [AC-10](./CanonicalSemanticModel.md#implementation-task--capability-activation); [SC-15](./CanonicalSemanticModel.md#end-to-end-semantic-scenarios) | [#132](https://github.com/philfanzhou/SignaCore/issues/132), [logout](./Logout.md) |
| Refresh theft, reuse, sibling-family confusion, or double rotation | Persist an exact code-to-family link, rotate within the family transaction, distinguish reuse from other rejection, and prove provider-specific concurrency | [PS-06, PS-07, PS-22](./CanonicalSemanticModel.md#artifact--persistence-relationship); [EV-29..33](./CanonicalSemanticModel.md#event--artifact--result); [SC-07, SC-14](./CanonicalSemanticModel.md#end-to-end-semantic-scenarios) | [#133](https://github.com/philfanzhou/SignaCore/issues/133), [refresh families](./RefreshTokens.md) |
| State changes race with redemption, refresh, UserInfo, or logout | Recheck current authority at each stateful surface and serialize on the named session/family/code rows | [EV-04, EV-05, EV-08..15, EV-23, EV-27..33](./CanonicalSemanticModel.md#event--artifact--result); [SC-05, SC-06, SC-10..12](./CanonicalSemanticModel.md#end-to-end-semantic-scenarios) | [#132](https://github.com/philfanzhou/SignaCore/issues/132), [state propagation](./StatePropagation.md), [#133](https://github.com/philfanzhou/SignaCore/issues/133) |
| Partial commit, cancellation, retry, or signing failure | Keep token bytes request-local until the durable transaction commits; roll back the unit; propagate cancellation; classify retry from committed state | [PS-22](./CanonicalSemanticModel.md#artifact--persistence-relationship); [EV-26](./CanonicalSemanticModel.md#event--artifact--result); [SC-16, SC-20](./CanonicalSemanticModel.md#end-to-end-semantic-scenarios) | [#131](https://github.com/philfanzhou/SignaCore/issues/131), [#133](https://github.com/philfanzhou/SignaCore/issues/133) |
| Secret disclosure through storage or diagnostics | Persist only specified digests/snapshots; redact headers, form/query carriers, and raw URIs; use synthetic canaries and bounded public ids | [DF-01..15](./CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow); [PS-11](./CanonicalSemanticModel.md#artifact--persistence-relationship) | [#129](https://github.com/philfanzhou/SignaCore/issues/129), [#134](https://github.com/philfanzhou/SignaCore/issues/134) |
| Cleanup destroys evidence or changes a child result | Retain consumed-code replay evidence for 24 hours and preserve referential integrity while any retained artifact points to a session/family | [persistence cleanup rule and PS-05..10](./CanonicalSemanticModel.md#artifact--persistence-relationship) | [#133](https://github.com/philfanzhou/SignaCore/issues/133), [persistence](./Persistence.md) |
| Metadata overclaims a partial deployment | Keep settings disabled and metadata absent until the complete slice and operational gate pass | [AC-01..14](./CanonicalSemanticModel.md#implementation-task--capability-activation) | [#129](https://github.com/philfanzhou/SignaCore/issues/129), [#134](https://github.com/philfanzhou/SignaCore/issues/134), [Discovery](./Discovery.md) |

## Audit contract

Protocol audit is a security side effect, not a substitute for transaction state. Rows promised by
an event commit in the same transaction as that event under [PS-11](./CanonicalSemanticModel.md#artifact--persistence-relationship).
The two fixed replay names are `oidc.code.replayed` from `EV-24` and `oidc.refresh.replayed` from
`EV-31`. SignaCore #71 must define a closed vocabulary for the remaining authorization, login,
issuance, UserInfo, logout, and state-change outcomes before implementation.

Every protocol audit record contains only the closed event name, outcome class, correlation id, UTC
time, and the bounded public record ids required to investigate the event. A transaction may include
an account, registered client, session, code, family, or logout-request id when the event already
resolved it. It never includes a submitted username that did not resolve, a raw URI, claim set,
credential, cookie, handle, code, verifier/challenge, token, `state`, or `nonce`. Existing non-OIDC
login-history behavior remains outside this target contract and is not silently reclassified here.

Negative tests must prove missing or merely invalid artifacts do not create replay audits, while a
committed consumed artifact creates exactly one replay audit even when another current-state check
also fails. Transaction rollback and cancellation tests must prove promised audit rows cannot commit
without their corresponding state change.

## Metrics contract

SignaCore #71 must expose enough signals to distinguish success, generic rejection, replay/reuse,
rate rejection, transaction rollback, and latency for each fixed OIDC endpoint class. It must also
expose bounded gauges for retained continuation, session, code, logout-request, and interactive-family
populations so cleanup and abnormal growth are observable.

Metric labels are an allowlist: fixed endpoint/operation name, closed outcome/reason enum, database
provider, and a bounded registered client id only when per-client diagnosis is necessary. Account,
session, code, family, request, and correlation ids; URI; username; IP address; claim; token; handle;
`state`; and `nonce` are never labels. This applies [DF-11 and DF-13](./CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow)
and the operational gate in [AC-13](./CanonicalSemanticModel.md#implementation-task--capability-activation),
as established by [#129](https://github.com/philfanzhou/SignaCore/issues/129).

## Rate-limit contract

Rate limiting runs before expensive client authentication or password verification, so invalid
credentials cannot bypass resource protection. The policy must cover fixed endpoint classes and
must not build unbounded partitions from attacker-controlled raw values. A resolved registered client
may receive a bounded client partition; unresolved traffic remains in a bounded source-network or
trusted-gateway partition. Login defense must preserve the generic credential result and existing account
lockout semantics.

Exact budgets, windows, queue behavior, shared-store or gateway enforcement, and overload response
shape belong to SignaCore #71 and must be fixed as testable product policy before that task is ready.
They are intentionally not invented by this design integration task. A multi-instance PostgreSQL
deployment must demonstrate one effective protection budget across replicas, whether enforced by
SignaCore shared state or the trusted ingress. Single-process in-memory limits alone do not satisfy
that gate. SQLite remains a single-instance topology under
[PS-22](./CanonicalSemanticModel.md#artifact--persistence-relationship).

Rate rejection must not redirect to an untrusted URI, consume one-time protocol artifacts, increment
the password failed-attempt counter, or echo the partition key. Production activation remains held by
[AC-13](./CanonicalSemanticModel.md#implementation-task--capability-activation) and the
[#129](https://github.com/philfanzhou/SignaCore/issues/129) / [#134](https://github.com/philfanzhou/SignaCore/issues/134)
design chain until #71 proves these properties.

## Sensitive-value verification

Implementation and tests consume [DF-01..15](./CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow)
directly. In addition to unit assertions, #71 must run synthetic canaries for every carrier: request
headers, query strings, form bodies, cookies, database rows, structured log properties, exception
messages, traces, audit snapshots, and metric labels. The test fails if any raw secret or
correlation-sensitive value appears. Digests are permitted only in the database relationships named
by `PS-*`; they are not diagnostic substitutes for correlation ids.

Browser endpoints use `Referrer-Policy: no-referrer`; login pages deny framing; credential and token
responses use `Cache-Control: no-store`; authorization callbacks and one-time-handle query values are
redacted from access logging. These requirements come from the canonical data-flow section and the
closed endpoint designs in [#130](https://github.com/philfanzhou/SignaCore/issues/130),
[#131](https://github.com/philfanzhou/SignaCore/issues/131), and
[#132](https://github.com/philfanzhou/SignaCore/issues/132).

## Release gate

Interactive OIDC may be enabled for internal end-to-end tests as each activation row permits, but it
is not production-ready until #71 proves the matrix, audit, metrics, limits, multi-instance behavior,
and canaries above. Passing this gate changes no Discovery field by itself (`AC-13`), as fixed by
[#129](https://github.com/philfanzhou/SignaCore/issues/129).

Primary standards references are [OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700),
[PKCE](https://www.rfc-editor.org/rfc/rfc7636),
[Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750), and
[Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207).
