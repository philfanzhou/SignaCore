# UserInfo Endpoint

**Status: target design.** See [README](./README.md).

`GET /oauth2/userinfo` returns claims about the subject of the presented access token (OIDC Core §5.3).

## Request

```
GET /oauth2/userinfo HTTP/1.1
Host: signacore.example.com
Authorization: Bearer <access token>
```

- `GET` only. `POST` with `access_token` in a form body is permitted by the specification and is not
  implemented: it is a second parsing path for a credential that has a header designed for it.
- The token MUST be in the `Authorization` header. A token in the query string is rejected — query
  strings land in access logs, proxy logs, and browser history.
- No client authentication. The access token is the credential.

## Validation

1. `Authorization` present, scheme `Bearer` (case-insensitive per RFC 7235), one token value.
2. Signature valid against the current JWKS.
3. `iss` matches, `exp` is in the future, `nbf`/`iat` are sane within 120 seconds of skew.
4. `typ` is `at+jwt`. An ID token presented here fails — it is `JWT` and its `aud` is a client, not
   a resource.
5. The token was issued through the authorization-code flow with `openid` in its granted scope.
6. The account still exists and is enabled.
7. The identity session named by `sid`, if the token carries one, has not been revoked.

Step 5 is what keeps this endpoint from becoming a profile API for the existing grants. A token from
`password` or `sms` has no granted scope and no `sid`, so it does not authorize a UserInfo call. That
is not an oversight: `/api/user/profile` already serves that need and its contract is frozen.

Step 7 means a signed-out user's access token stops working here even before it expires. UserInfo
reads live account state, so serving it from a revoked session would be answering a question the
user has already withdrawn.

## Response

```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "sub": "00000000-0000-0000-0000-000000000000",
  "name": "example.operator",
  "nickname": "Example Operator"
}
```

| Claim | Presence | Source |
| --- | --- | --- |
| `sub` | Always | The account's stable identifier; identical to `sub` in the ID token |
| `name` | Only with `profile` | Account username |
| `nickname` | Only with `profile` | Account nickname, omitted when unset |

With `openid` alone, the response is `{"sub": "..."}` and nothing else. Claims not in the granted
scope are absent, not null: a null would say "this person has no name", which is a different
statement from "you did not ask".

Never returned: `role`, `Permission`, `auth_method`, `client_id`, phone number, email, LDAP
distinguished name, WeChat openid, password state, lockout state, or any other credential or
account-security detail. UserInfo answers "who is this", not "what may they do" and not "how are
they secured". Roles and permissions travel in the access token, where the audience restriction
applies to them.

The response is unsigned JSON. Signed and encrypted UserInfo responses (`application/jwt`) are not
implemented; `userinfo_signing_alg_values_supported` is therefore absent from discovery.

`sub` MUST equal the `sub` of the ID token the client received. A client that finds otherwise must
treat the response as invalid (OIDC Core §5.3.2).

## Errors

RFC 6750 §3.1 `WWW-Authenticate`, not an OAuth error object.

| Condition | Status | `WWW-Authenticate` |
| --- | --- | --- |
| No `Authorization` header | 401 | `Bearer` |
| Malformed header, or a token in the query | 400 | `Bearer error="invalid_request"` |
| Bad signature, expired, wrong issuer, wrong `typ` | 401 | `Bearer error="invalid_token"` |
| Token has no `openid` scope, or was not issued interactively | 403 | `Bearer error="insufficient_scope", scope="openid"` |
| Account disabled or deleted | 401 | `Bearer error="invalid_token"` |
| Identity session revoked | 401 | `Bearer error="invalid_token"` |
| Rate limited | 429 | Problem-details body, existing shape |
| Internal failure | 500 | Problem-details body, existing shape |

`error_description` is omitted. Telling a caller *why* a token is invalid tells an attacker holding
a stolen token what to fix.

## CORS

No CORS headers. Every caller in this phase is a confidential BFF making a server-to-server request,
and a browser has no business holding an access token here. When the Public SPA epic ships, adding
CORS is a decision that belongs to it, with its own origin allow list.

## Rate limiting

| Partition | Limit |
| --- | --- |
| `userinfo:{sub}` | 120 / minute |
| `userinfo:{client_ip}` | 240 / minute |

A BFF that calls UserInfo on every request is doing it wrong — the claims belong in its own session —
so these limits are generous enough for correct use and tight enough to matter for a loop.
