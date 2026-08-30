# Authorization Endpoint

**Status: target design.** Read the [directory boundary](./README.md) and the
[canonical model](./CanonicalSemanticModel.md) first.

`GET /oauth2/authorize` is the browser entry point for the confidential-BFF code flow. `POST` is not
supported in this phase. The endpoint accepts attacker-controlled URL input, so it separates two
questions: whether SignaCore has a trustworthy redirect destination, and what protocol result can be
sent there.

## External fields

Canonical rows `IN-01` through `IN-09` own encoding, length, normalization, comparison, duplication,
sensitivity, and errors. This table is an index, not a second field definition:

| Field group | Canonical rows |
| --- | --- |
| `response_type` | `IN-01` |
| `client_id` | `IN-02` |
| `redirect_uri` | `IN-03` |
| `scope` | `IN-04` |
| `state` | `IN-05` |
| `nonce` | `IN-06` |
| `code_challenge` | `IN-07` |
| `code_challenge_method` | `IN-08` |
| Rejected and unknown parameters | `IN-09` |

The S256 challenge rule is intentionally narrower than the generic RFC 7636 `code-challenge` ABNF.
This phase accepts only the exact 43-character unpadded base64url output of
`BASE64URL(SHA256(ASCII(code_verifier)))`, so `.` and `~` cannot create a code that no verifier could
redeem. The verifier itself retains the RFC 7636 unreserved alphabet at token redemption (`IN-24`).

## Validation and redirect trust

The ordering paragraph after `IN-15` is normative. An implementation can express it as these stages:

| Stage | Decision source | Routing boundary |
| --- | --- | --- |
| Parameter cardinality for client and URI | `IN-02`, `IN-03` | Duplicate or malformed values stay local |
| Current application lookup and capability | `IN-02`, `PS-01`, `PS-21` | Unknown, inactive, or non-interactive application stays local |
| Exact registered redirect match | `IN-03`, `PS-20` | Missing or unmatched URI stays local |
| Remaining parameter cardinality and protocol checks | `IN-01`, `IN-04`–`IN-09` | Only now can an OAuth/OIDC error use the verified URI |
| Current identity and account check | `PS-04`, state vocabulary | No usable session enters the protected login continuation; rejected account follows canonical safe routing |

A submitted redirect URI is data, not a destination, until all first three stages succeed. The local
error page sets no `Location`, does not turn the submitted URI into a link, does not reveal whether a
client exists, and contextually encodes any diagnostic text.

After redirect trust is established, protocol errors use the exact response boundary in `PS-17`.
Error descriptions come from a closed English set and never include credentials, account/session
identifiers, raw input, exceptions, or stack traces. Failures that `PS-17` does not classify as
redirected protocol errors remain local.

## Identity continuation

When the request is valid but no acceptable identity session exists, SignaCore persists the request
behind the server-side continuation defined by `PS-03` and sends only `login_handle` to the login
page. No `returnUrl`, redirect URI, scope, state, nonce, or PKCE value is rendered into the login
form. [Identity Login](./IdentityLogin.md) owns the browser interaction and current-policy
revalidation.

An acceptable session can proceed directly. Session authority and activity come from the database;
the cookie is only a protected identifier. This document does not redefine session expiry or state
propagation, which remain canonical model concerns and later #132 prose.

## Authorization response

`PS-17` owns both successful and redirected-error shapes. Success uses query response mode and
returns a new code, byte-for-byte `state`, and authorization-server `iss` to the exact verified URI.
The response contains no token. Code persistence, consumption, and token redemption are deliberately
outside #130 and are explained by later tasks.

Every response is no-store/no-cache/no-referrer. The code necessarily crosses the browser boundary,
but `DF-03` limits it to the authorization response and BFF callback, while `DF-11` and `DF-12`
constrain state, nonce, and URI handling. Raw query values are excluded from access, audit, metric,
and trace output.

Two valid authorization requests for the same session and application are independent. They do not
deduplicate or overwrite one another. Canonical scenario `SC-07` carries the complete later outcome;
this document stops at the fact that two distinct codes are created.

## Implementation and compatibility

#93 implements validation and safe error routing; #94 later composes the session/continuation and
code-creation path. Neither task advertises the endpoint before the complete flow reaches activation
row `AC-07`.

Current `/oauth2/token`, `/oauth2/revoke`, `/api/auth/*`, claims callbacks, administration routes,
Discovery documents, and management cookie remain unchanged. This document does not register a
route or enable an application.
