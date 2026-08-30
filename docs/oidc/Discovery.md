# Discovery

**Status: target design.** See [README](./README.md).

`DiscoveryDocument` states what the service does, not what it intends to do. The existing comment in
that file is the rule: *advertising a capability that does not exist is worse than omitting it — a
conforming client would build a request it can never complete.*

## Today

`response_types_supported` is `[]`, there is no `authorization_endpoint`, no `userinfo_endpoint`, and
no `end_session_endpoint`. That is accurate: SignaCore is an OAuth 2.0 authorization server and is
not an OpenID Provider. Nothing in this directory changes that until the corresponding endpoint
ships.

## The rule

A discovery field is added in **the same pull request that makes its capability real**, never
earlier and never in a preparatory change. Concretely:

| Field | Added by the task that ships | Value |
| --- | --- | --- |
| `authorization_endpoint` | `GET /oauth2/authorize` | `{origin}/oauth2/authorize` |
| `response_types_supported` | Same | `["code"]` |
| `response_modes_supported` | Same | `["query"]` |
| `code_challenge_methods_supported` | Same | `["S256"]` |
| `grant_types_supported` gains `authorization_code` | The token-endpoint grant | Derived from the registered validators, as today |
| `scopes_supported` | The scope implementation | `["openid", "profile", "offline_access"]` |
| `userinfo_endpoint` | `GET /oauth2/userinfo` | `{origin}/oauth2/userinfo` |
| `claims_supported` gains `auth_time`, `sid`, `amr`, `nonce` | ID token issuance | Appended to the existing list |
| `end_session_endpoint` | `GET /oauth2/logout` | `{origin}/oauth2/logout` |

`sid` enters `claims_supported` as an ID token claim. The same claim is also carried by interactive
access tokens, and so is `scope` ([Tokens](./Tokens.md#access-token)), but neither is registered on
that account: `claims_supported` describes the claims a client may ask this provider for in an ID
token or a UserInfo response, and an access token is opaque to the client that receives it. `scope`
is therefore never listed there — `scopes_supported` is where a client learns which scope values
exist.

`grant_types_supported` is already derived from the registered validators rather than from a
literal, so `authorization_code` appears there automatically when the grant is registered. That is
the pattern the other fields should follow where they can.

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

The endpoint tasks in the epic land in the order authorize → token grant → tokens → userinfo →
logout, so discovery grows monotonically and is never wrong at any commit. If an implementation task
merges without its discovery field, the document understates the service — recoverable, and the next
pull request fixes it. The reverse is what must not happen.

## Tests

The existing discovery unit tests are extended, not replaced, by each task:

- The document contains exactly the fields for capabilities that exist, and no others.
- `grant_types_supported` matches the registered validators.
- `issuer` equals the `iss` claim of an issued token and the `iss` parameter of an authorization
  response. These three come from one configured value and a test asserts they agree.
- Every advertised endpoint URL resolves to a route that the host actually maps.

The last one is the useful test. A typo in `{origin}/oauth2/userinfo` is invisible in review and
fatal for a conforming client.
