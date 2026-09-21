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
> binding through the optional `ReferenceBffDatabase` configuration below. The BFF-owned storage
> lives in `samples/SignaCore.ReferenceBff.Database` (with its SQLite migration project
> `samples/SignaCore.ReferenceBff.Database.Migrations.Sqlite`) and carries three tables: the
> single initial-administrator binding slot (`management_role_bindings`, staging and exact-match
> read via `ManagementRoleBindingStore`) and the two shared ServiceMantle tables
> (`service_installations` and `service_audit_logs`) mapped through the pinned
> `ServiceMantle.Persistence.EntityFrameworkCore` package — never a local clone of a shared
> entity. The BFF's fixed ServiceMantle service id is `reference-bff`, not the product's
> `signacore`. Nothing migrates or binds automatically at runtime, and the first-installation
> (Setup) flow is still a later task.

## Database (data phase)

`ReferenceBffDbContext` implements the shared `IServiceDbContext` contract, and
`AddReferenceBffServiceMantleStores` registers the scoped `IServiceInstallationStore` and
`IManagementAuditWriter` over the same caller-owned scoped context. The extension registers
stores only — it never configures a database provider, opens a connection, or initializes an
installation row or an administrator.

Two save semantics coexist by contract:

- `EfCoreManagementAuditWriter.RecordAsync` only **stages** an audit record on the caller's
  context; the caller decides when to save and commit, so the audit write always joins the unit
  of work the caller already owns.
- `CreatePendingAsync` is the shared library's one initialization entry point that **owns a
  single `SaveChangesAsync`**, and it requires a clean context: calling it while other entities
  are staged is refused. Completing an installation still belongs to the later Setup-flow task
  (validate → orchestrate → stage-consume → one save → commit) and is not invoked here.

Apply each provider's own migrations explicitly before running anything against this database
(the commands are in the Configuration section below); nothing migrates or seeds automatically
at startup. Rollback limits: code-only rollbacks keep the three tables in place, but migrating
`Down` past the shared-tables migration deletes `service_installations` and `service_audit_logs`
with their data — the binding table is untouched, yet a backup is still mandatory, `Down` must
only ever be rehearsed on an isolated copy, and a completed installation must never be restored
to `Pending` by re-importing a dropped row. This stage deliberately does not open the
first-installation (Setup) flow.

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

## Local Setup Code (operations phase)

After explicitly migrating the independent BFF database above, inject
`ReferenceBffDatabase__Provider` (`SQLite` or `PostgreSQL`) and
`ReferenceBffDatabase__ConnectionString` through your protected environment. In a protected local
interactive terminal, run one of:

```bash
dotnet run --project samples/SignaCore.ReferenceBff -- --setup-code create
dotnet run --project samples/SignaCore.ReferenceBff -- --setup-code rotate
```

These mutually exclusive commands require both stdin and stdout to be terminals. Do not pipe,
redirect, capture, or record the output. No OIDC configuration or SignaCore connection is required;
the command never starts a web listener, migrates, or writes a bootstrap file. Its only arguments
are the command and verb; database secrets belong in the protected environment, never arguments.
Normal web startup still initializes nothing and supports sign-in without a database.

The command consumes the shared ServiceMantle lifecycle under one serializable transaction.
`create` initializes a missing installation through `CreatePendingAsync`, then creates its first
code. It refuses to replace existing material. `rotate` requires an existing Pending installation
and existing material (including expired material). Completed installations and occupied
administrator slots (active or inactive) are always refused. The shared store owns the digest,
generation, version and default 30-minute lifetime; no plaintext is persisted. Role and audit
rows are unchanged. See [the authoritative operations model](https://github.com/philfanzhou/SignaCore/issues/74)
for the lifecycle and recovery boundaries.

Only after commit and successful cleanup is the code displayed once. Exit codes are `0` for
commit plus display, `2` for usage/terminal rejection, `3` for state/concurrency rejection, `4` for
dependency/save/commit/cleanup/display failure or unknown commit outcome, and `130` for caller
cancellation. Errors contain only fixed English categories. Nothing retries automatically.
A failure or cancellation after commit may leave a generated code that the operator never saw.
Check the installation independently and recover with an explicitly controlled `rotate` when
appropriate; do not assume a failed command means nothing was committed. A code-only rollback
retains all installation data, code digests and bindings. Never use migration `Down`, deletion,
or resetting Completed to Pending as code recovery.

This phase does **not** enable Setup HTTP or bind an administrator. The later
[HTTP first-binding task](https://github.com/philfanzhou/SignaCore/issues/326) consumes the code
after verified OIDC sign-in; until that phase is delivered, a Pending installation still denies
management. Protect database access and the terminal, and use TLS for that later HTTP flow.
The command does not protect against terminal recording, an OS administrator or process-memory
inspection, and does not promise cross-process exactly-once delivery.

## Run

```bash
ReferenceBff__ClientSecret='<injected-client-secret>' \
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
