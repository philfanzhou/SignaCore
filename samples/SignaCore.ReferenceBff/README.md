# SignaCore Reference BFF

A minimal reference Browser-for-Frontend (BFF) that signs administrators in to a SignaCore
server through Authorization Code + PKCE (S256), keeps every token in a server-side session, and
exposes only an opaque local cookie to the browser.

The sample resolves the authorization, token, JWKS, and UserInfo endpoints from the Authority's
OpenID Connect Discovery document. Nothing is hardcoded.

> **Single-instance reference.** The session ticket store is in-process memory: a restart loses
> sessions and replicas do not share them. Replace it with a shared store before running more
> than one instance. Coordinated upstream logout and the first-administrator binding flow are
> delivered by later SignaCore tasks.
>
> **Runtime authorization over an optional local database.** The sample's sign-in keeps working
> with no database at all; `GET /bff/admin` additionally enforces the local administrator
> binding. The BFF-owned storage lives in `samples/SignaCore.ReferenceBff.Database` (with its
> SQLite migration project `samples/SignaCore.ReferenceBff.Database.Migrations.Sqlite`): the
> single initial-administrator slot with independent PostgreSQL and SQLite migration histories,
> plus the staging and exact-match read boundary (`ManagementRoleBindingStore`). Open it through
> the optional `ReferenceBffDatabase` configuration below — nothing migrates or binds
> automatically at runtime, and the first-installation (Setup) flow is still a later task.

## Configuration

| Key | Meaning |
| --- | --- |
| `ReferenceBff:Authority` | SignaCore base address (HTTPS) |
| `ReferenceBff:ClientId` | Client id registered in SignaCore |
| `ReferenceBff:ClientSecret` | Client secret — inject through the environment or user secrets |
| `ReferenceBff:RedirectUri` | This host's HTTPS redirect URI (default path `/signin-oidc`) |
| `ReferenceBff:Scope` | Requested scope (must contain `openid`) |
| `ReferenceBffDatabase:Provider` | Optional local database provider: `SQLite` or `PostgreSQL` |
| `ReferenceBffDatabase:ConnectionString` | Optional local database connection string |

The configuration is validated at startup; an incomplete configuration fails to start. The two
`ReferenceBffDatabase` keys must be provided together, and a partial or unknown combination fails
startup with a fixed message that echoes no value. With both omitted, the sample runs exactly its
login-only shape and every authenticated management query answers a fixed `503`.

Before first use, create and migrate the database explicitly — the runtime never migrates,
creates schema, or seeds:

```bash
# PostgreSQL
dotnet ef database update --project samples/SignaCore.ReferenceBff.Database \
  --startup-project samples/SignaCore.ReferenceBff.Database

# SQLite
dotnet ef database update --project samples/SignaCore.ReferenceBff.Database.Migrations.Sqlite \
  --startup-project samples/SignaCore.ReferenceBff.Database.Migrations.Sqlite
```

An empty migrated database denies management (`403`); a missing schema or an unreachable database
answers a fixed `503` without ever widening permission.

Register the redirect URI on the SignaCore application (interactive OIDC configuration) with the
code flow enabled before using the sample.

## Run

```bash
SIGNACORE_REFERENCE_BFF_CLIENT_SECRET=... \
dotnet run --project samples/SignaCore.ReferenceBff \
  --ReferenceBff:Authority=https://your-signacore-host \
  --ReferenceBff:ClientId=reference-bff \
  --ReferenceBff:RedirectUri=https://your-bff-host/signin-oidc \
  --ReferenceBffDatabase:Provider=SQLite \
  --ReferenceBffDatabase:ConnectionString="Data Source=signacore-reference-bff.db"
```

Then open `https://your-bff-host/` and follow **Sign in with SignaCore**.

## Security shape

- SignaCore credentials never pass through this BFF: the browser is redirected to SignaCore's
  authorization endpoint, and the password is posted directly to SignaCore's own login form.
- Every login uses a fresh `state`, `nonce`, and PKCE verifier; the correlation cookie is
  `Secure`, `HttpOnly`, and `SameSite=None` for the top-level redirect back.
- The ID token is validated for `iss`, signature (via JWKS), `exp`/`iat`, `nonce`, and `aud`
  (the client id). A failure of any of them fails the sign-in; no local session is established.
- A missing or mismatching `state` or correlation cookie fails the callback before any token
  exchange.
- Tokens are saved into a server-side ticket store (`ITicketStore`); the browser receives only
  the opaque `Secure`, `HttpOnly`, `SameSite=Lax` session key cookie. No token material is
  stored in the browser, rendered into HTML, or placed in a URL.
- The access token is used only on the server-to-server `GET /bff/me` call to SignaCore's
  Discovery-resolved UserInfo endpoint. A UserInfo `401` (the upstream identity session is gone)
  revokes the local session and answers the bounded error page — the BFF never keeps a
  signed-in appearance over a dead upstream session.
- The only state-changing browser surface is `POST /bff/logout`, protected by antiforgery; it
  clears the local cookie and the server-side ticket. There is no GET logout.
- Expired tickets are reclaimed both when presented and by a periodic background sweep.

## Runtime authorization (`GET /bff/admin`)

Authentication and authorization are deliberately separate decisions in this sample:

- At sign-in, the validated ID token's issuer and its single non-empty `sub` are captured
  byte-for-byte into the server-side ticket. The configured Authority is never treated as the
  verified issuer, and a token without exactly one usable subject fails the sign-in. A ticket
  from before this capture cannot prove an identity and is rejected with a re-login.
- Every management request re-confirms the identity live: one Discovery-resolved UserInfo call
  carrying the stored access token, whose successful JSON object must contain exactly one string
  `sub` Ordinal-equal to the captured subject. Nothing about the administrator decision is cached
  across requests.
- Only then is the exact local active binding matched (`issuer` + `subject`, Ordinal, no
  normalization, no generic admin claim). Deactivating the binding takes effect on the very next
  request.
- The responses are fixed and carry no identity or token: `200 {"isAdministrator":true}` when the
  exact binding holds; `401` when the session can no longer prove a valid upstream identity (the
  ticket is torn down); `403` for a local denial (the ticket is kept); `503` when a dependency
  cannot answer (the ticket is kept). Anonymous requests take the standard OIDC challenge back to
  the fixed `/bff/admin` route only — no open return URL.
- `GET /bff/me` keeps its original contract: the confirmed profile payload is passed through,
  and its failure paths remain the bounded redirect pages.

## Scope

This is a sample consumer of SignaCore, not a product. The ticket store is single-instance
memory; coordinated upstream logout, the first-administrator binding (Setup) flow, and deployment
hardening beyond the boundaries above are intentionally left out — the runtime authorization
slice proves the shape, not a production administrator console.
