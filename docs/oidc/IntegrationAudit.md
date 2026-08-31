# Interactive OIDC Integration Audit

**Audit date: 2026-08-31. Result: closed with no contradictory result or missing execution point.**

This ledger records the final semantic replay required by #134. Expected results remain defined only
by [SC-01..20](./CanonicalSemanticModel.md#end-to-end-semantic-scenarios); this file records which
input, persistence, event, and data-flow rows were traversed and which explanatory contract was
checked. It is not a second state matrix.

Each trace explicitly lists the external-input contracts evaluated (`IN`), persisted or
response-authority artifacts read or written (`PS`), event and transaction rows executed (`EV`),
and sensitive-value boundaries crossed (`DF`). Ranges are inclusive; `optional` identifies a
canonical branch rather than an omitted artifact. Rows not listed are not part of that scenario.

| Scenario | Semantic trace evaluated | Explanatory contracts checked | Audit result |
| --- | --- | --- | --- |
| `SC-01` | `IN-01..15, IN-20..25`; `PS-01..05, PS-06` (optional), `PS-09..14, PS-17..22`; `EV-01, EV-20/21`; `DF-01..08, DF-09` (optional), `DF-11..14` | [authorization](./AuthorizationEndpoint.md), [login](./IdentityLogin.md), [redemption](./TokenEndpoint.md), [tokens](./Tokens.md) | Closed: authorization, login, no-refresh redemption, and optional-family redemption each reach one owned commit and response boundary |
| `SC-02` | `IN-01..15`; `PS-01, PS-03, PS-17, PS-19, PS-21`; `EV-09`; `DF-01, DF-05, DF-11..13` | [login](./IdentityLogin.md), [client model](./ClientModel.md), [authorization](./AuthorizationEndpoint.md) | Closed: current-client rejection is reached before session, code, token, or redirect authority is created |
| `SC-03` | `IN-01..15`; `PS-01..03, PS-17, PS-19..21`; `EV-12`; `DF-01, DF-05, DF-11/12` | [authorization](./AuthorizationEndpoint.md), [login](./IdentityLogin.md), [client model](./ClientModel.md) | Closed: the stored URI snapshot and current registration meet at the required local-error boundary |
| `SC-04` | `IN-01..15`; `PS-01..03, PS-17, PS-19..21`; `EV-13`; `DF-01, DF-05, DF-11/12` | [authorization](./AuthorizationEndpoint.md), [login](./IdentityLogin.md), [client model](./ClientModel.md) | Closed: current client/URI trust and current scope rejection converge on one safe no-narrowing response owner |
| `SC-05` | `IN-20..25, IN-30..36`; `PS-01/02, PS-04/05, PS-06` (families when present), `PS-08..12, PS-18, PS-20..22`; `EV-06, EV-23, EV-28` (logout-first); `DF-02..04, DF-06, DF-08, DF-10..14` | [logout](./Logout.md), [redemption](./TokenEndpoint.md), [session](./IdentitySession.md), [persistence](./Persistence.md) | Closed: the logout request and session lock lead to the sole logout-first outcome without consuming the code or creating replay evidence |
| `SC-06` | `IN-20..25, IN-28..36`; `PS-01/02, PS-04/05, PS-06` (optional), `PS-08..14, PS-18, PS-20..22`; `EV-20/21, EV-28` (redemption-first), `EV-06`; `DF-02..04, DF-06..14` | [redemption](./TokenEndpoint.md), [tokens](./Tokens.md), [logout](./Logout.md), [UserInfo](./UserInfo.md) | Closed: issuance commits before every logout write, while token lifetime and stateful UserInfo authority remain separately owned |
| `SC-07` | two `IN-01..09` and `IN-20..25` evaluations; `PS-01/02, PS-04..06, PS-09..14, PS-17/18, PS-20..22`; two `EV-21` transactions; `DF-02..04, DF-06..09, DF-11..14` | [authorization](./AuthorizationEndpoint.md), [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md), [persistence](./Persistence.md) | Closed: each code-to-root association is committed directly and neither transaction needs an inferred family selector |
| `SC-08` | repeated `IN-20..25`; `PS-01, PS-04..06, PS-09..14, PS-22`; `EV-21, EV-24`; `DF-02..04, DF-07..09, DF-13/14` | [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md), [session](./IdentitySession.md), [security](./Security.md) | Closed: committed consumption selects only the linked family and the separately owned session-wide effect and id-only audit |
| `SC-09` | repeated `IN-20..25`; `PS-01, PS-04/05, PS-09..14, PS-22`; `EV-20, EV-24`; `DF-02..04, DF-07/08, DF-13/14` | [redemption](./TokenEndpoint.md), [persistence](./Persistence.md), [security](./Security.md) | Closed: the persisted null family link is executable and leaves no path that could select an unrelated family |
| `SC-10` | `IN-01..09, IN-20..29`; `PS-01, PS-03..06, PS-09, PS-13, PS-17/18, PS-21/22`; `EV-04, EV-23, EV-32`; `DF-02..07, DF-09, DF-11..13` | [session](./IdentitySession.md), [authorization](./AuthorizationEndpoint.md), [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md), [UserInfo](./UserInfo.md) | Closed: code, refresh, UserInfo, next-authorization, and downstream-token projections all use their canonical time and state authorities |
| `SC-11` | `IN-01..09, IN-20..29`; `PS-01, PS-03..06, PS-09, PS-13, PS-16/17, PS-21/22`; `EV-13, EV-23, EV-32`; `DF-02..05, DF-07/09, DF-11..13, DF-15` | [client model](./ClientModel.md), [authorization](./AuthorizationEndpoint.md), [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md), [UserInfo](./UserInfo.md) | Closed: policy removal reaches distinct pending, code, family, UserInfo, and self-contained-token owners without a narrowing branch |
| `SC-12` | `IN-20..29`; `PS-01, PS-04..06, PS-09, PS-13, PS-22`; `EV-09, EV-23, EV-32`; `DF-02..04, DF-07/09, DF-13` | [state propagation](./StatePropagation.md), [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md), [UserInfo](./UserInfo.md), [session](./IdentitySession.md) | Closed: application-owned code, family, and UserInfo failures do not supply a path to erase global session or other-client state |
| `SC-13` | two `IN-20..25` evaluations; `PS-01, PS-04/05, PS-06` (optional), `PS-09/10, PS-12..14, PS-22`; `PS-11` for issuance and replay audits; `EV-25`, winner `EV-20/21`, loser `EV-24`; `DF-02..04, DF-07/08, DF-09` (optional), `DF-13/14` | [redemption](./TokenEndpoint.md), [tokens](./Tokens.md), [persistence](./Persistence.md), [security](./Security.md) | Closed: session/code locking, conditional consumption, optional root creation, token release, and replay audit have one serial execution |
| `SC-14` | two `IN-20, IN-26/27` evaluations; `PS-01, PS-04, PS-06, PS-09/10, PS-12/13/15, PS-22`; `PS-11` for issuance and reuse audits; `EV-30`, winner `EV-29`, loser `EV-31`; `DF-02, DF-07..09, DF-13/14` | [refresh families](./RefreshTokens.md), [tokens](./Tokens.md), [persistence](./Persistence.md), [security](./Security.md) | Closed: the interactive family row, one-child constraint, response boundary, and reuse audit produce the same single-winner execution on both providers |
| `SC-15` | `IN-30..36`; `PS-01/02, PS-04, PS-06` (families when present), `PS-08..12, PS-18, PS-20..22`; `EV-06/07`; `DF-02, DF-06, DF-08..14` | [logout](./Logout.md), [session](./IdentitySession.md), [persistence](./Persistence.md), [security](./Security.md) | Closed: authenticated preparation, non-persisted ID token, persisted request, browser handle, matching cookie, and indistinguishable completion branches have explicit owners |
| `SC-16` | `IN-20..25`; `PS-01, PS-04/05, PS-06` (optional), `PS-09/10, PS-12..14, PS-22`; rolled-back `PS-11`; `EV-26`; `DF-02..04, DF-07/08, DF-09` (optional), `DF-13/14` | [redemption](./TokenEndpoint.md), [tokens](./Tokens.md), [persistence](./Persistence.md), [security](./Security.md) | Closed: code, optional family/link, audit, signing authority, token construction, and response all remain inside the failed issuance boundary |
| `SC-17` | `IN-31`; `PS-09/10, PS-12/13/15`; `EV-16`; `DF-07/08/14` | [tokens](./Tokens.md), [logout](./Logout.md), [security](./Security.md) | Closed: the signing-key authority alone connects new issuance, JWKS retention, token expiry, and logout-hint validation without a state-artifact write |
| `SC-18` | continuation: `IN-10/11, PS-03, EV-03, DF-05`; code: `IN-20..25, PS-05, EV-22, DF-02..04`; interactive refresh: `IN-20, IN-26/27, PS-06, EV-32, DF-02/09`; logout: `IN-35, PS-08, DF-10`; shared no-audit authority: `PS-11` | [login](./IdentityLogin.md), [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md), [logout](./Logout.md), [security](./Security.md) | Closed: every missing lookup stops at its own artifact and cannot manufacture consumption, revocation, association, session selection, or replay audit |
| `SC-19` | invalid-CSRF branch: `IN-11, IN-14/15, PS-03/19, DF-05`; credential branch: `IN-11..15, PS-03/11/19, EV-17, DF-01/05/13` | [login](./IdentityLogin.md), [security](./Security.md) | Closed: structural/CSRF rejection and syntactically valid credential failure meet distinct work boundaries without changing continuation or exposing credential cause |
| `SC-20` | `IN-11..15, IN-20..27, IN-35/36`; `PS-01..06, PS-08..15, PS-17..22`; `EV-18` around `EV-01, EV-06, EV-20/21, EV-29..31`; `DF-01..14` | [login](./IdentityLogin.md), [redemption](./TokenEndpoint.md), [tokens](./Tokens.md), [refresh families](./RefreshTokens.md), [logout](./Logout.md), [persistence](./Persistence.md) | Closed: each one-time input, write set, generated response, and retry classification shares the same before/after-commit boundary |

## Cross-document review

- All event outcomes are referenced from the canonical model; no explanatory file defines a
  competing state value or transition table.
- Every artifact required by a promised state effect has a persisted direct relationship. Nullable
  relationships have an explicit executable result instead of an inferred association.
- Every external field has a cardinality, encoding, length, normalization/comparison, sensitivity,
  and failure owner.
- Every sensitive carrier terminates at the boundary named by `DF-01..15`; no prose permits a raw
  token, credential, handle, `state`, or `nonce` in diagnostics.
- The activation graph has no path from route existence to premature metadata. Operational release
  is a separate gate and prepared logout never claims standard wire compatibility.

The twelve review threads from superseded PR #127 were also mapped to the closed design decisions in
#129..#133 and the Discovery gate in #134; no thread requires reopening a predecessor. The mapping is
recorded on [issue #134](https://github.com/philfanzhou/SignaCore/issues/134#issuecomment-5472311690).
