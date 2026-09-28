# Discovery Capability Activation

**Status: activation history and current metadata.** Current behavior is also recorded in
[Standards Conformance](../overview/StandardsConformance.md); the normative activation rules are
[AC-01..14](./CanonicalSemanticModel.md#implementation-task--capability-activation).

## Current fact

`DiscoveryDocument` serves identical metadata at `/.well-known/openid-configuration` and
`/.well-known/oauth-authorization-server`. It publishes the configured issuer, JWKS, the standards
`/oauth2/authorize`, `/oauth2/token`, `/oauth2/revoke`, and `/oauth2/userinfo` endpoints,
`response_types_supported: ["code"]`, the `authorization_code` grant, S256 PKCE, and the supported
interactive scopes. `token_endpoint_auth_methods_supported` is
`["client_secret_basic", "client_secret_post", "none"]`; `none` applies only to an enabled Public
authorization-code client using S256 and a form `client_id`. The revoke endpoint still supports only
`client_secret_basic` and `client_secret_post`. Public refresh requires a committed
`offline_access` Code family and the current explicit bounded policy; `none` alone grants nothing.
The metadata does not enable Public revoke or other Public grants. Exact registered Public Origin
CORS for Code-token, refresh-token, and UserInfo responses is a separate host policy, not inferred
from this metadata.
It does not publish a standard
`end_session_endpoint`.

## Activation graph

The graph below records the implementation and release ordering at design time, not a second protocol
state model or a description of current runtime availability. Every runtime result remains defined by
the linked canonical rows and closed design task.

The prerequisite column is a 2026-08-31 snapshot of GitHub's native dependency graph. It lists only
direct `Blocked by` edges for every implementation task named in a gate; it never substitutes a
transitive ancestor. `A ← B, C` means that task A is directly blocked by B and C. Cross-repository
tasks are qualified with their repository name.

| Gate | Named task ← direct native prerequisites | Capability effect | Public metadata effect | Contract source |
| --- | --- | --- | --- | --- |
| `AC-01` | #61 ← #48, #134 | #61 stores disabled-by-default interactive policy | None | [AC-01](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#130](https://github.com/philfanzhou/SignaCore/issues/130) |
| `AC-02` | #64 ← [ServiceMantle#40](https://github.com/philfanzhou/ServiceMantle/issues/40), [ServiceMantle#41](https://github.com/philfanzhou/ServiceMantle/issues/41), #48, #134; #65 ← #64; #66 ← #64, #65 | Isolated identity cookie, Password login, and continuation can be exercised internally | None | [AC-02](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#130](https://github.com/philfanzhou/SignaCore/issues/130) |
| `AC-03` | #50 ← #48, #61, #95, #134 | #50 persists and atomically consumes codes for internal tests | None | [AC-03](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#131](https://github.com/philfanzhou/SignaCore/issues/131) |
| `AC-04` | #93 ← #61 | #93 validates authorize requests and safe error routing | None | [AC-04](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#130](https://github.com/philfanzhou/SignaCore/issues/130) |
| `AC-05` | #94 ← #50, #64, #65, #66, #93 | #94 can issue a bound code | None; a code alone is not a complete advertised flow | [AC-05](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#130](https://github.com/philfanzhou/SignaCore/issues/130) |
| `AC-06` | #53 ← #50, #94 | #53 redeems code with PKCE | None until the OIDC core slice closes | [AC-06](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#131](https://github.com/philfanzhou/SignaCore/issues/131) |
| `AC-07` | #54 ← #53, #96 | Confidential-BFF code flow includes ID token and live persistent-session checks | Atomically add `authorization_endpoint`, `code`, `authorization_code`, `S256`, supported interactive scopes, and actual auth methods | [AC-07](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#131](https://github.com/philfanzhou/SignaCore/issues/131) |
| `AC-08` | #55 ← #54 | #55 makes UserInfo usable with current-state checks | Add `userinfo_endpoint` only now | [AC-08](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#132](https://github.com/philfanzhou/SignaCore/issues/132) |
| `AC-09` | #67 ← #52, #64, #65, #66; #69 ← #53, #55, #94, #96 | Session lifecycle and state propagation become enforceable | None | [AC-09](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#132](https://github.com/philfanzhou/SignaCore/issues/132) |
| `AC-10` | #68 ← #49, #96 | #68 provides authenticated preparation and one-time browser completion | Never add standard `end_session_endpoint` for this nonstandard wire shape | [AC-10](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#132](https://github.com/philfanzhou/SignaCore/issues/132) |
| `AC-11` | #97 ← #53, #95, #133 | #97 adds exact interactive family persistence | Do not add `offline_access` | [AC-11](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#133](https://github.com/philfanzhou/SignaCore/issues/133) |
| `AC-12` | #98 ← #96, #97, #133 | #98 closes atomic rotation, reuse handling, and session enforcement | Add `offline_access` only now; the already truthful `refresh_token` grant remains | [AC-12](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#133](https://github.com/philfanzhou/SignaCore/issues/133) |
| `AC-13` | #71 ← #53, #55, #94, #96, [ServiceMantle#83](https://github.com/philfanzhou/ServiceMantle/issues/83), [ServiceMantle#84](https://github.com/philfanzhou/ServiceMantle/issues/84), [ServiceMantle#86](https://github.com/philfanzhou/ServiceMantle/issues/86), [ServiceMantle#88](https://github.com/philfanzhou/ServiceMantle/issues/88), [ServiceMantle#142](https://github.com/philfanzhou/ServiceMantle/issues/142) | Product-specific limits, audit, metrics, and sensitive canaries pass | None; production release remains disabled until the gate passes | [AC-13](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#129](https://github.com/philfanzhou/SignaCore/issues/129), [#134](https://github.com/philfanzhou/SignaCore/issues/134) |
| `AC-14` | #134 ← #130, #131, #132, #133 | The English target contract is complete | Current metadata remains byte-for-byte unchanged | [AC-14](./CanonicalSemanticModel.md#implementation-task--capability-activation), [#129](https://github.com/philfanzhou/SignaCore/issues/129), [#134](https://github.com/philfanzhou/SignaCore/issues/134) |

`AC-07` publishes only scopes that are usable at that point. In particular, `offline_access` remains
absent through `AC-11` and appears only at `AC-12`. `AC-10` never turns the prepared logout route into
standard logout metadata. These constraints come from the linked canonical rows, not from route
existence.

## Implementation checks

Each metadata-changing implementation task must:

1. derive issuer and endpoint origins through the existing validated configuration path;
2. update both Discovery paths from one document builder;
3. add negative tests proving premature fields remain absent;
4. add positive end-to-end tests before advertising a capability;
5. assert exact endpoint, response type, grant, PKCE method, scope, claim, and client-auth values;
6. keep metadata absent while its activation prerequisites are incomplete, and keep production
   activation disabled until the `AC-13` gate passes.

The metadata vocabulary follows [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) and
[OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html).
