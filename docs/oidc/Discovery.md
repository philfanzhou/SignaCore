# Discovery

**Status: target design.** See [README](./README.md).

`DiscoveryDocument` states what the service does, not what it intends to do. The existing comment in
that file is the rule: *advertising a capability that does not exist is worse than omitting it — a
conforming client would build a request it can never complete.*

## Today

`response_types_supported` is `[]`, there is no `authorization_endpoint`, no `userinfo_endpoint`, and
no `end_session_endpoint`. That is accurate: SignaCore is an OAuth 2.0 authorization server and is
not an OpenID Provider. Nothing in this directory changes that until the first usable interactive
OIDC flow ships as a coherent capability.

`id_token_signing_alg_values_supported` is already present as `["RS256"]`. It records the only
algorithm the existing key ring can supply; with no authorization endpoint and an empty
`response_types_supported`, it does not by itself make an ID-token flow usable. Core-flow activation
retains and verifies this existing value rather than adding it for the first time.

## The rule

A discovery field is added in **the same pull request that makes its advertised capability usable
end to end**, never earlier and never in a preparatory change. The core authorization-code fields
form one capability: none is advertised until authorization, code redemption, and ID-token issuance
all work together. Concretely:

| Field | Published or updated by | Value |
| --- | --- | --- |
| `authorization_endpoint` | Core-flow activation in #54, after authorize + code grant + ID token all work | `{origin}/oauth2/authorize` |
| `response_types_supported` | Same #54 activation | `["code"]` |
| `response_modes_supported` | Same #54 activation | `["query"]` |
| `code_challenge_methods_supported` | Same #54 activation | `["S256"]` |
| `grant_types_supported` gains `authorization_code` | Same #54 activation | The staged validator becomes advertised |
| `scopes_supported` | Same #54 activation | `["openid", "profile", "offline_access"]` |
| `id_token_signing_alg_values_supported` | Already present; verified unchanged by #54 | `["RS256"]` |
| `userinfo_endpoint` | `GET /oauth2/userinfo` | `{origin}/oauth2/userinfo` |
| `claims_supported` gains `auth_time`, `sid`, `amr`, `nonce` | Same #54 activation | Appended to the existing list |
| `end_session_endpoint` | `GET /oauth2/logout` | `{origin}/oauth2/logout` |

`sid` enters `claims_supported` as an ID token claim. The same claim is also carried by interactive
access tokens, and so is `scope` ([Tokens](./Tokens.md#access-token)), but neither is registered on
that account: `claims_supported` describes the claims a client may ask this provider for in an ID
token or a UserInfo response, and an access token is opaque to the client that receives it. `scope`
is therefore never listed there — `scopes_supported` is where a client learns which scope values
exist.

`grant_types_supported` is derived from registered validators today. The `authorization_code`
validator is the one staged exception: #53 registers and tests the grant, but the discovery
projection withholds that value until #54 can publish the complete flow. #54 removes the staging
filter while publishing the other core fields. After activation, derivation again describes the
whole registered set; at every commit, every *advertised* grant still has a real validator.

## Fields that stay absent

| Field | Why |
| --- | --- |
| `request_object_signing_alg_values_supported` | Request objects are rejected |
| `userinfo_signing_alg_values_supported` | UserInfo returns plain JSON |
| `acr_values_supported` | No `acr` is issued, and none is reserved |
| `claims_parameter_supported` | Omitting it means `false`; stating `false` is also acceptable |
| `frontchannel_logout_supported`, `backchannel_logout_supported` | Not implemented |
| `introspection_endpoint` | No introspection in this phase |
| `registration_endpoint` | No dynamic registration |

Absent is the correct encoding for "not supported" for most of these; a client that needs the
capability sees nothing to call.

## Ordering

Preparatory tasks may land routes, persistence, and issuance components in dependency order, but the
core OIDC discovery fields above move together only in the task that activates a complete
authorization-code flow (#54). Until then, discovery continues to understate those staged internal
pieces, including the registered grant. UserInfo and logout remain independent additions: each
endpoint is advertised when that endpoint itself ships. Discovery therefore grows monotonically
without ever inviting a conforming client into a flow it cannot complete.

## Tests

The existing discovery unit tests are extended, not replaced, by each task:

- The document contains exactly the fields for capabilities that exist, and no others.
- Every advertised grant has a registered validator. Before #54 the staged `authorization_code`
  validator is deliberately omitted; after #54 the advertised and registered sets match exactly.
- `issuer` equals the `iss` claim of an issued token and the `iss` parameter of an authorization
  response. These three come from one configured value and a test asserts they agree.
- Every advertised endpoint URL resolves to a route that the host actually maps.

The last one is the useful test. A typo in `{origin}/oauth2/userinfo` is invisible in review and
fatal for a conforming client.
