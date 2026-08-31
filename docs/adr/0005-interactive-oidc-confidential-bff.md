# Interactive OIDC for Confidential BFF Clients

- Status: Accepted
- Date: 2026-08-31
- Decision owners: SignaCore maintainers

## Context

SignaCore currently exposes standards-shaped OAuth token, revocation, Discovery, and JWKS surfaces,
but it is not an OpenID Provider. The target is an interactive identity flow for pre-registered,
first-party administrative applications without exposing credentials or tokens to browser code.

The [canonical semantic model](../oidc/CanonicalSemanticModel.md) is the only normative source for
state transitions, persistence relationships, input rules, sensitive-data flows, and capability
activation. This ADR records why those decisions were selected; it does not restate a second state
machine.

## Decision

| Decision | Normative source | Closed design task and explanation |
| --- | --- | --- |
| Support only pre-registered confidential BFF clients in the first phase; keep secrets, the PKCE verifier, and every token server-side | [PS-01, PS-20, PS-21](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship); [DF-02, DF-04, DF-07..09](../oidc/CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow) | [#130](https://github.com/philfanzhou/SignaCore/issues/130), [client model](../oidc/ClientModel.md) |
| Use Authorization Code with mandatory PKCE S256, exact redirect matching, mandatory state/nonce, and query response mode | [IN-01..09](../oidc/CanonicalSemanticModel.md#authorization-and-identity-login); [PS-17](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship) | [#130](https://github.com/philfanzhou/SignaCore/issues/130), [authorization endpoint](../oidc/AuthorizationEndpoint.md) |
| Isolate the browser identity cookie from the management cookie and make the database session row authoritative across instances | [PS-04, PS-18, PS-19](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship); [EV-01..05](../oidc/CanonicalSemanticModel.md#event--artifact--result) | [#130](https://github.com/philfanzhou/SignaCore/issues/130), [#132](https://github.com/philfanzhou/SignaCore/issues/132), [identity login](../oidc/IdentityLogin.md), [identity session](../oidc/IdentitySession.md) |
| Store authorization codes as short-lived digests, bind them to exact snapshots, and consume them atomically only with successful issuance | [PS-03, PS-05](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship); [IN-22..25](../oidc/CanonicalSemanticModel.md#token-and-userinfo); [EV-20..28](../oidc/CanonicalSemanticModel.md#event--artifact--result) | [#131](https://github.com/philfanzhou/SignaCore/issues/131), [code redemption](../oidc/TokenEndpoint.md) |
| Issue distinct ID and access tokens; use per-application audience and preserve the access-token boundary at downstream resources | [PS-12..16](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship); [DF-07..08](../oidc/CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow) | [#131](https://github.com/philfanzhou/SignaCore/issues/131), [interactive tokens](../oidc/Tokens.md) |
| Make UserInfo a server-side Bearer surface that rechecks application, account, session, and current claim policy | [IN-28..29](../oidc/CanonicalSemanticModel.md#token-and-userinfo); [PS-16](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship); [EV-04, EV-05, EV-08, EV-09, EV-13, EV-15](../oidc/CanonicalSemanticModel.md#event--artifact--result) | [#132](https://github.com/philfanzhou/SignaCore/issues/132), [UserInfo](../oidc/UserInfo.md) |
| Use authenticated logout preparation followed by a one-time browser handle; do not advertise a standard `end_session_endpoint` | [IN-30..36](../oidc/CanonicalSemanticModel.md#logout-without-an-id-token-in-the-browser); [DF-08, DF-10](../oidc/CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow); [AC-10](../oidc/CanonicalSemanticModel.md#implementation-task--capability-activation) | [#132](https://github.com/philfanzhou/SignaCore/issues/132), [prepared logout](../oidc/Logout.md) |
| Give each interactive authorization its own refresh family, rotate atomically, revoke on reuse, and keep legacy refresh behavior isolated | [PS-06, PS-07](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship); [EV-24, EV-29..33](../oidc/CanonicalSemanticModel.md#event--artifact--result); [IN-26..27](../oidc/CanonicalSemanticModel.md#token-and-userinfo) | [#133](https://github.com/philfanzhou/SignaCore/issues/133), [refresh families](../oidc/RefreshTokens.md), [persistence](../oidc/Persistence.md) |
| Publish each Discovery capability only after its complete dependency slice is usable, and hold production release until operational protections pass | [AC-01..14](../oidc/CanonicalSemanticModel.md#implementation-task--capability-activation) | [#129](https://github.com/philfanzhou/SignaCore/issues/129), [#134](https://github.com/philfanzhou/SignaCore/issues/134), [Discovery activation](../oidc/Discovery.md), [security gate](../oidc/Security.md) |

## Consequences

- A browser never handles a client secret, PKCE verifier, access token, ID token, or refresh token.
- A database-backed identity session becomes an explicit protocol authority and must be implemented
  symmetrically for PostgreSQL and single-writer SQLite.
- Self-contained access and ID tokens remain valid until their own expiry. Immediate current-state
  enforcement is available only at SignaCore stateful surfaces such as token redemption and UserInfo.
- Prepared logout is deliberately product-specific in this phase. It protects the ID token from URL
  exposure but is not RP-Initiated Logout wire compatibility.
- Existing grants, management cookies, legacy refresh rows, and current Discovery remain compatible
  until the activation rows explicitly change them.

## Alternatives considered

| Alternative | Reason rejected | Normative source and task |
| --- | --- | --- |
| Let each administrative application collect a SignaCore password | It duplicates credential handling and cannot provide a shared browser identity session | [DF-01](../oidc/CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow), [SC-01](../oidc/CanonicalSemanticModel.md#end-to-end-semantic-scenarios), [#130](https://github.com/philfanzhou/SignaCore/issues/130) |
| Start with a public SPA client | Browser token storage, public-client policy, and consent are outside the first-phase trust model | [PS-01](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship), [guarantees](../oidc/CanonicalSemanticModel.md#guarantees-and-caller-responsibilities), [#130](https://github.com/philfanzhou/SignaCore/issues/130) |
| Reuse the management-console cookie | It would merge operator administration and delegated identity authority | [PS-18](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship), [#130](https://github.com/philfanzhou/SignaCore/issues/130) |
| Make PKCE optional or accept `plain` | It weakens the code interception boundary and creates a configurable downgrade | [IN-07, IN-08](../oidc/CanonicalSemanticModel.md#authorization-and-identity-login), [PS-21](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship), [#130](https://github.com/philfanzhou/SignaCore/issues/130) |
| Use stateless authorization codes | Replay, rollback, exact-family association, and cross-instance single consumption require persisted state | [PS-03, PS-05 and PS-22](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship), [#131](https://github.com/philfanzhou/SignaCore/issues/131) |
| Publish `/oauth2/authorize` before ID-token and session enforcement are complete | A conforming client would discover a flow it cannot safely finish | [AC-05..07](../oidc/CanonicalSemanticModel.md#implementation-task--capability-activation), [#131](https://github.com/philfanzhou/SignaCore/issues/131) |
| Put `id_token_hint` in a browser logout URL | Browser history, proxies, and access logs would receive an ID token | [DF-08](../oidc/CanonicalSemanticModel.md#sensitive-value--trust-boundary-and-data-flow), [IN-30..35](../oidc/CanonicalSemanticModel.md#logout-without-an-id-token-in-the-browser), [AC-10](../oidc/CanonicalSemanticModel.md#implementation-task--capability-activation), [#132](https://github.com/philfanzhou/SignaCore/issues/132) |
| Infer a refresh family from account, client, session, or scope | Concurrent authorizations may create sibling families; replay must select only the persisted exact link | [PS-05..07](../oidc/CanonicalSemanticModel.md#artifact--persistence-relationship), [SC-07..09](../oidc/CanonicalSemanticModel.md#end-to-end-semantic-scenarios), [#133](https://github.com/philfanzhou/SignaCore/issues/133) |
| Revoke self-contained access tokens immediately on every state change | There is no introspection or access-token row in this phase; downstream validation remains local | [EV-03..05](../oidc/CanonicalSemanticModel.md#event--artifact--result), [caller responsibilities](../oidc/CanonicalSemanticModel.md#guarantees-and-caller-responsibilities), [#132](https://github.com/philfanzhou/SignaCore/issues/132) |

## Standards basis

The decision follows [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html),
[OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html),
[RFC 6749](https://www.rfc-editor.org/rfc/rfc6749),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636),
[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414),
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207), and
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700). The prepared logout transport is intentionally
not a claim of conformance with RP-Initiated Logout 1.0.
