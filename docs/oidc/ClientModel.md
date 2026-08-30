# Interactive Client Model

**Status: target design.** See [README](./README.md).

An *application* (`app_registrations`) stays the unit of registration. Interactive capability is an
opt-in extension of an existing application, not a second kind of entity.

## A callback is not a redirect URI

This is the single most dangerous confusion in this feature, so it is stated before anything else.

| | Claims callback (`app_registrations.callback_url`) | Redirect URI |
| --- | --- | --- |
| Direction | SignaCore makes a server-to-server HTTP request **to** the application | SignaCore sends the **browser** to the application |
| When | During token issuance, to collect the application's claims for an account | At the end of an authorization request |
| Carries | An account identifier out, claims back | An authorization code, or an error, in the query string |
| Chosen by | Configuration only; never influenced by a request | Named in every authorization request and therefore attacker-influenced |
| Matching | Not matched against anything; it is simply dialled | Exact equality against a registered set |
| Failure impact | Claims are missing; issuance continues with basic claims | An authorization code is delivered to whoever controls the URI |

Rules that follow:

- `callback_url` MUST NOT be read, copied, defaulted, or offered as a suggestion when registering a
  redirect URI, in the API or in the admin console.
- A redirect URI MUST NOT be written into `callback_url`.
- The two sets are independent: a value may legitimately appear in both, and that is a coincidence
  of deployment topology, not a relationship the system records.
- Existing applications gain no redirect URI when the interactive feature ships. An application with
  an empty redirect-URI set cannot start an authorization request, regardless of any other setting.

## Interactive client configuration

Fields below are the contract. Their physical placement — columns on `app_registrations` versus a
companion table — is settled in [Persistence](./Persistence.md).

| Field | Type | Default | Rules |
| --- | --- | --- | --- |
| `allow_authorization_code` | bool | `false` | When `false`, `/oauth2/authorize` refuses this `client_id` and `grant_type=authorization_code` is refused at the token endpoint |
| `client_type` | enum | `Confidential` | Only `Confidential` is accepted in this phase. `Public` is reserved for the SPA epic and MUST be rejected on write until that epic ships |
| `allowed_scopes` | set | `{openid}` | Subset of `{openid, profile, offline_access}`. MUST contain `openid`. `offline_access` MUST NOT be present unless `allow_refresh_token` is `true` |
| `allow_refresh_token` | bool | `false` | A refresh token is issued only when this is `true` **and** `offline_access` was granted |
| `redirect_uris` | ordered set | empty | 0–10 entries, each ≤ 500 characters, unique per application after normalization |
| `post_logout_redirect_uris` | ordered set | empty | 0–10 entries, same syntax rules as `redirect_uris` |
| `identity_session_max_age` | duration | inherits deployment default | Optional per-application cap on identity-session age accepted at `/oauth2/authorize`; MUST NOT exceed the deployment absolute lifetime |

Invariants that are deliberately **not** configuration, because a per-client switch is a downgrade
waiting to be flipped:

- PKCE is always required, and `code_challenge_method` is always `S256`.
- `response_type` is always `code`.
- `response_mode` is always `query`.
- Consent is never shown; every client is first-party and administrator-approved.
- The `state` and `nonce` parameters are always required.

## Audience

An application with `allow_authorization_code = true` MUST have `audience_mode = PerApplication`.

- Enabling the flow on an application whose mode is `Shared` MUST fail with a message naming the
  required migration, not silently flip the mode: flipping it changes the audience of tokens issued
  by grants that are already in production.
- Setting `audience_mode = Shared` on an application that already allows the authorization code flow
  MUST fail for the same reason.
- The migration order for an existing application is unchanged from
  [StandardsConformance](../overview/StandardsConformance.md): teach the downstream validator both
  audiences, flip to `PerApplication`, drop the shared audience, and only then enable the
  interactive flow.

## Redirect URI syntax

A registered redirect URI MUST satisfy all of the following. A value failing any rule is rejected at
registration time with a message naming the specific rule; a value that somehow exists in storage
and fails a rule at request time is treated as unregistered.

| Rule | Requirement | Rationale |
| --- | --- | --- |
| Encoding | ASCII only; a non-ASCII host MUST be registered in its A-label (punycode) form | Two spellings of one host must not compare unequal |
| Length | 1–500 characters | Matches `MaxCallbackUrlLength`; bounds index size |
| Form | Absolute URI with an authority component | A relative reference has no destination |
| Scheme | `https`, compared lowercase | Codes must not travel in cleartext |
| Loopback exception | `http://127.0.0.1[:port]/…` and `http://[::1][:port]/…` are accepted **only** when the host runs in the Development environment | A confidential BFF in production is reachable over TLS |
| `localhost` | Rejected, in every environment | It resolves through DNS and through the hosts file, so it is not equivalent to a loopback literal |
| Userinfo | Rejected | `https://user:pass@host/` is both a credential in configuration and a well-known spoofing vector |
| Fragment | Rejected | RFC 6749 §3.1.2 forbids it, and a fragment never reaches the server |
| Query | Permitted, and part of the exact match | Some frameworks mount callbacks with a fixed query |
| Wildcards | Rejected — no `*`, no prefix match, no path-suffix match, no port range | Every pattern language eventually matches something its author did not intend |
| Duplicates | Rejected within one application after normalization | Two rows meaning the same destination make revocation ambiguous |

### Registration-time normalization

Normalization happens exactly once, on write, and the normalized value is what is stored, displayed,
and compared. Requests are **not** normalized.

1. Lowercase the scheme.
2. Lowercase the host. IPv6 literals keep their brackets.
3. Remove the port when it is the scheme default (`443` for `https`).
4. Where the path is empty, set it to `/`.
5. Leave everything else — path case, percent-encoding, query, trailing slash — exactly as supplied.

Step 5 is the important one. `%2F` is not `/`, `/Callback` is not `/callback`, and
`/callback/` is not `/callback`. Canonicalising further would let one registration stand for several
destinations, which is the property the exact-match rule exists to remove.

### Request-time comparison

`redirect_uri` from an authorization or token request is compared to each stored value with ordinal,
case-sensitive string equality. No normalization, no parsing, no URI-object comparison. If no stored
value matches, the request is rejected and — critically — **nothing is redirected**; see
[AuthorizationEndpoint](./AuthorizationEndpoint.md#error-routing).

Examples, for an application that registered exactly `https://console.example.com/signin-oidc`:

| Request value | Result |
| --- | --- |
| `https://console.example.com/signin-oidc` | Match |
| `https://console.example.com/signin-oidc/` | No match — trailing slash |
| `https://console.example.com/Signin-Oidc` | No match — path case |
| `https://console.example.com:443/signin-oidc` | No match — the registered value has no port, and requests are not normalized |
| `https://console.example.com/signin-oidc?x=1` | No match — extra query |
| `https://console.example.com.attacker.test/signin-oidc` | No match — different host |
| `http://console.example.com/signin-oidc` | No match — different scheme |

The `:443` row is a deliberate strictness: normalizing the request would mean parsing
attacker-controlled input with the same parser twice and trusting both results to agree. Clients
send back the string they were configured with, so the cost is a registration that has to be exact.

## Scopes

| Scope | Meaning | Effect |
| --- | --- | --- |
| `openid` | Required in every authorization request | An `id_token` is issued; `/oauth2/userinfo` accepts the access token |
| `profile` | Optional | `name` and `nickname` appear in the ID token and UserInfo response |
| `offline_access` | Optional, and only when the application allows it | A refresh token is issued with the token response |

Request-side rules are in [AuthorizationEndpoint](./AuthorizationEndpoint.md#request-parameters). Granted scope
is always echoed in the token response, so a client can detect a downgrade — for example, an
application whose `offline_access` permission was withdrawn between two logins.

## Client authentication

Unchanged from the existing token endpoint: `client_secret_basic` or `client_secret_post`, with the
secret verified against `app_secret_hash`. The legacy `X-Admin-AppId` / `X-Admin-AppSecret` headers
remain unaccepted at `/oauth2/*`. The authorization endpoint itself is not client-authenticated —
it is reached by a browser — which is exactly why the code is useless without the secret and the
`code_verifier`.

## Administration surface

The management API and admin console tasks (#62, #63) expose these fields. Two rules bind them:

- A redirect URI list is edited as a whole set with an explicit save; an "add" control MUST NOT
  prefill from `callback_url` or from any previous value.
- Removing a redirect URI takes effect immediately for new authorization requests. It does not
  invalidate codes already issued for that URI; those expire within 60 seconds on their own.
