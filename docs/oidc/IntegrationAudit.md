# Interactive OIDC Integration Audit

**Audit date: 2026-08-31. Result: closed with no contradictory result or missing execution point.**

This ledger records the final semantic replay required by #134. Expected results remain defined only
by [SC-01..20](./CanonicalSemanticModel.md#end-to-end-semantic-scenarios); this file records which
input, persistence, event, and data-flow rows were traversed and which explanatory contract was
checked. It is not a second state matrix.

| Scenario | Semantic trace evaluated | Explanatory contracts checked | Audit result |
| --- | --- | --- | --- |
| `SC-01` | `IN-01..15 → PS-01..05/18..20 → EV-01 → IN-20..25 → EV-20/21`; `DF-01..07` | [authorization](./AuthorizationEndpoint.md), [login](./IdentityLogin.md), [redemption](./TokenEndpoint.md), [tokens](./Tokens.md) | Closed: every input, transaction, response, and secret has one owner |
| `SC-02` | `IN-02/03/10..15 → EV-09`; `DF-01/05/12` | [login](./IdentityLogin.md), [client model](./ClientModel.md) | Closed: current-client rejection executes before code or redirect |
| `SC-03` | `IN-03/10..15 → EV-12`; `PS-02/20`, `DF-12` | [authorization](./AuthorizationEndpoint.md), [login](./IdentityLogin.md) | Closed: exact current URI is rechecked at the continuation boundary |
| `SC-04` | `IN-04/10..15 → EV-13`; `PS-21`, `DF-11/12` | [authorization](./AuthorizationEndpoint.md), [login](./IdentityLogin.md) | Closed: safe redirect and no-narrowing rules share one current policy check |
| `SC-05` | `IN-35/36 → EV-06`; then `IN-20..25 → EV-23/28`; `PS-04..07` | [logout](./Logout.md), [redemption](./TokenEndpoint.md), [session](./IdentitySession.md) | Closed: the common session lock produces the logout-first serial result |
| `SC-06` | `EV-20/21 → EV-28 → EV-06`; `PS-04..07/12..16` | [redemption](./TokenEndpoint.md), [logout](./Logout.md), [UserInfo](./UserInfo.md) | Closed: committed tokens and immediate stateful rejection have distinct owners |
| `SC-07` | two `EV-21` transactions; `PS-05..07`; `DF-03/09/13` | [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md), [persistence](./Persistence.md) | Closed: each code persists its own family link; no inference path remains |
| `SC-08` | `EV-21 → EV-24`; `PS-05..07/11`; `DF-03/09/13` | [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md), [security](./Security.md) | Closed: replay reaches only the exact link and session-owned sibling effect |
| `SC-09` | `EV-20 → EV-24`; nullable `PS-05` link; `DF-03/13` | [redemption](./TokenEndpoint.md), [persistence](./Persistence.md) | Closed: null is an executable association and cannot select another family |
| `SC-10` | expiry `EV-04 → EV-23/32`; `PS-03/04/06`; `IN-22/26/29` | [session](./IdentitySession.md), [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md), [UserInfo](./UserInfo.md) | Closed: all three stateful surfaces share captured-time authority without changing downstream JWT expiry |
| `SC-11` | `EV-13 → EV-23/32`; `IN-04/27/29`; `PS-06/16/21` | [client model](./ClientModel.md), [refresh families](./RefreshTokens.md), [UserInfo](./UserInfo.md) | Closed: pending, family, UserInfo, and downstream-token effects remain distinct |
| `SC-12` | `EV-09 → EV-23/32`; `PS-01/04/06`; `IN-02/20/29` | [state propagation](./StatePropagation.md), [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md) | Closed: application-owned revocation does not erase the identity session or other clients |
| `SC-13` | `EV-25 → EV-24` for the loser; `PS-22` | [redemption](./TokenEndpoint.md), [persistence](./Persistence.md) | Closed: provider locking plus conditional consumption has one winning commit and one replay path |
| `SC-14` | two `EV-30` attempts converging on `EV-31`; `PS-06/07/22` | [refresh families](./RefreshTokens.md), [persistence](./Persistence.md) | Closed: one child and one family-reuse result are executable on both providers |
| `SC-15` | `IN-30..36 → EV-06/07`; `PS-08`; `DF-08/10/11/12` | [logout](./Logout.md), [security](./Security.md) | Closed: the token and browser handle cross disjoint trust boundaries |
| `SC-16` | `EV-26`; transaction-owned `PS-03/05/07/11`; `DF-03/07..09` | [redemption](./TokenEndpoint.md), [persistence](./Persistence.md), [security](./Security.md) | Closed: no durable or response artifact exists outside the issuance transaction boundary |
| `SC-17` | `EV-16`; `PS-12/15`; `IN-31`; `DF-08/14` | [tokens](./Tokens.md), [logout](./Logout.md) | Closed: validation retention covers token expiry and the fixed logout-hint window |
| `SC-18` | `EV-03/22/32`; `IN-10/22/26/35`; `PS-11` | [login](./IdentityLogin.md), [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md), [logout](./Logout.md) | Closed: missing lookup paths invent neither state nor replay evidence |
| `SC-19` | `IN-14` rejects before credential work; valid `IN-11..15 → EV-17`; `PS-19`; `DF-01/05` | [login](./IdentityLogin.md), [security](./Security.md) | Closed: CSRF and credential failures reach different internal work but the promised bounded external shapes |
| `SC-20` | `EV-18` before/after `EV-01/06/20/21/29..31`; `PS-22` | [login](./IdentityLogin.md), [redemption](./TokenEndpoint.md), [refresh families](./RefreshTokens.md), [logout](./Logout.md) | Closed: the commit boundary determines the sole retry classification at every stateful surface |

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
