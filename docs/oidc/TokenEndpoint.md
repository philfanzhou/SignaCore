# Token Endpoint: `authorization_code`

**Status: target design.** See [README](./README.md).

`POST /oauth2/token` gains one grant type. Everything already there —
`password`, `sms`, `ldap`, `wechat_code`, `refresh_token`, `client_secret_basic` /
`client_secret_post` authentication, the `no-store` headers, the RFC 6749 §5.2 error shape — is
unchanged. `/api/auth/token` gains nothing: the legacy contract is frozen and this grant is not
added to it.

## Request

`Content-Type: application/x-www-form-urlencoded`, client authenticated as today.

| Parameter | Required | Bounds | Rule |
| --- | --- | --- | --- |
| `grant_type` | Yes | — | Exactly `authorization_code` |
| `code` | Yes | Exactly 43 chars, `[A-Za-z0-9._~-]` | The value from the authorization response |
| `redirect_uri` | Yes | 1–500 chars | MUST equal, byte-for-byte, the `redirect_uri` of the authorization request |
| `code_verifier` | Yes | 43–128 chars, `[A-Za-z0-9._~-]` (RFC 7636 §4.1) | Verified against the stored challenge |
| `scope` | No — rejected | — | Present → `invalid_request`. Scope is fixed at authorization time |

The authenticated client MUST be the client the code was issued to. A code issued to application A
and presented by application B fails with `invalid_grant`, not `invalid_client`: B authenticated
successfully, so the client is valid; the grant is not.

`redirect_uri` is required and compared against the stored value, not against the registered set.
RFC 6749 §4.1.3 requires it, and it closes a real gap: a client with two registered redirect URIs
whose code was issued for one must not be able to redeem it while claiming the other.

## Verification order

1. Client authentication (existing pipeline). Failure → `invalid_client`, HTTP 401.
2. `grant_type` is `authorization_code`, and the application has `allow_authorization_code = true`.
   Failure → `unauthorized_client`.
3. `code`, `redirect_uri`, `code_verifier` present and within bounds; `scope` absent. Failure →
   `invalid_request`.
4. Compute the code digest and load the record. Missing → `invalid_grant`.
5. The record's `client_id` equals the authenticated client. Mismatch → `invalid_grant`.
6. The record is not consumed. Consumed → `invalid_grant` **and replay handling below**.
7. The record has not expired. Expired → `invalid_grant`.
8. The record's `redirect_uri` equals the request's, ordinal. Mismatch → `invalid_grant`.
9. PKCE: `BASE64URL(SHA256(ASCII(code_verifier)))` equals the stored `code_challenge`, compared in
   constant time. Mismatch → `invalid_grant`.
10. Consume the record atomically. Lost race → `invalid_grant` and replay handling.
11. The account is still enabled and the application still active. Otherwise → `invalid_grant`.
12. Issue tokens.

Every failure from step 4 onward returns the same `invalid_grant` with the same
`error_description` — `"The authorization code is invalid, expired, or has already been used."` —
and takes an indistinguishable amount of time to answer. Distinguishing "expired" from "wrong
verifier" tells an attacker holding a stolen code whether it is still worth attacking.

## Single-use consumption

Consumption is one atomic conditional update, not a read followed by a write:

```sql
UPDATE authorization_codes
   SET consumed_at = @now
 WHERE code_digest = @digest
   AND consumed_at IS NULL
   AND expires_at > @now
RETURNING account_id, client_id, redirect_uri, scope, nonce, identity_session_id, auth_time;
```

Exactly one concurrent caller gets a row; the other gets zero rows and fails. `RETURNING` is what
makes it one statement — a `SELECT` before the `UPDATE` reintroduces the window the statement exists
to close. On SQLite the same statement is used; the guarantee comes additionally from there being
one writer, which is why [Persistence](./Persistence.md) keeps SQLite single-instance.

The digest is computed by the same construction as refresh tokens (`RefreshTokenDigest`): SHA-256 of
the ASCII code, lowercase hex, `sha256:` prefix, 71 characters, unique-indexed. The plaintext code is
never stored, never logged, and never appears in an audit record.

## Replay handling

Presenting an already-consumed code is treated as evidence that the code leaked, because a correct
client never does it.

1. The request fails with `invalid_grant`.
2. The refresh token family issued by the first redemption of that code, if any, is revoked.
3. The identity session recorded on the code is revoked.
4. An audit record is written naming the application, the account, and the code's identifier — never
   the code.

Step 3 goes beyond the minimum. If a code leaked, the browser flow that produced it is suspect, and
the cheapest correct response is to make the user log in again. This is a deliberate availability
cost paid for a specific, rare signal.

Access tokens already issued from the first redemption are **not** revoked: they are self-contained
and short-lived, and there is no revocation list. Their short lifetime is the bound; see
[Tokens](./Tokens.md#access-token).

## Success response

```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 900,
  "id_token": "<JWT>",
  "scope": "openid profile",
  "refresh_token": "<opaque>"
}
```

- `id_token` appears whenever the grant is `authorization_code`, which is always, since `openid` is
  required.
- `scope` is the **granted** scope, space-delimited, in the order `openid profile offline_access`.
  It is always present so a client can detect a downgrade against what it asked for.
- `refresh_token` appears only when the application allows it *and* `offline_access` was granted.
- The existing grants' responses do not change: they still carry no `scope` and no `id_token`.

## Refresh at an interactive client

`grant_type=refresh_token` for a token minted interactively behaves as it does today — rotation on
use, the old token revoked — with two additions:

- The response carries a new `id_token` and the same granted `scope`. The new ID token gets a fresh
  `iat`/`exp` and carries forward the original `auth_time` and `sid`; it MUST NOT carry the original
  `nonce`, which belongs to one authorization request only.
- If the identity session named by `sid` has been revoked, the refresh fails with `invalid_grant`.
  A refresh token issued interactively does not outlive the session it came from.

Reuse of a consumed refresh token revokes every live descendant of its family, not only the token
presented. See [Tokens](./Tokens.md#reuse-detection); the behaviour is delivered by #97 and #98
inside this phase, and the existing grants keep today's rotation semantics unchanged.

## Error matrix

| Condition | `error` | HTTP |
| --- | --- | --- |
| Client authentication failed or absent | `invalid_client` | 401 |
| `grant_type` unknown | `unsupported_grant_type` | 400 |
| `allow_authorization_code` is false | `unauthorized_client` | 400 |
| Missing/malformed `code`, `redirect_uri`, `code_verifier`; `scope` present | `invalid_request` | 400 |
| Code unknown, expired, consumed, wrong client, wrong redirect URI, or wrong verifier | `invalid_grant` | 400 |
| Account disabled or application deactivated between authorization and redemption | `invalid_grant` | 400 |
| Signing key unavailable, database unreachable | `server_error` | 500 |

## Rate limiting

| Partition | Limit |
| --- | --- |
| `token:code:{client_id}` | 120 / minute |
| `token:code:{client_ip}` | 60 / minute |

A 429 is the existing problem-details body, never an OAuth error object: `temporarily_unavailable`
would tell a client to retry, which is the opposite of what a limiter wants.
