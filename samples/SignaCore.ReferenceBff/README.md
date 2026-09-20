# SignaCore Reference BFF

A minimal reference Browser-for-Frontend (BFF) that signs administrators in to a SignaCore
server through Authorization Code + PKCE (S256), keeps every token in a server-side session, and
exposes only an opaque local cookie to the browser.

The sample resolves the authorization, token, JWKS, and UserInfo endpoints from the Authority's
OpenID Connect Discovery document. Nothing is hardcoded.

> **Single-instance reference.** The session ticket store is in-process memory: a restart loses
> sessions and replicas do not share them. Replace it with a shared store before running more
> than one instance. First-administrator binding and coordinated upstream logout are delivered by
> later SignaCore tasks.
>
> **Storage data phase — not wired into the runtime yet.** `samples/SignaCore.ReferenceBff.Database`
> — with its SQLite migration project `samples/SignaCore.ReferenceBff.Database.Migrations.Sqlite` —
> owns the BFF's independent database. It carries three tables: the single
> initial-administrator binding slot (`management_role_bindings`, staging and exact-match read via
> `ManagementRoleBindingStore`) and the two shared ServiceMantle tables (`service_installations`
> and `service_audit_logs`) mapped through the pinned
> `ServiceMantle.Persistence.EntityFrameworkCore` package — never a local clone of a shared
> entity. The BFF's fixed ServiceMantle service id is `reference-bff`, not the product's
> `signacore`. The running sample still authenticates without any local database: runtime
> configuration and authorization are wired by later slices, and this stage opens no Setup flow.

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

Apply the migrations explicitly before running anything against this database; nothing migrates
or seeds automatically at startup. Each provider keeps its own history:

```bash
# PostgreSQL (history lives in SignaCore.ReferenceBff.Database)
dotnet ef database update --project samples/SignaCore.ReferenceBff.Database \
  --startup-project samples/SignaCore.ReferenceBff.Database

# SQLite (history lives in SignaCore.ReferenceBff.Database.Migrations.Sqlite)
dotnet ef database update --project samples/SignaCore.ReferenceBff.Database.Migrations.Sqlite \
  --startup-project samples/SignaCore.ReferenceBff.Database.Migrations.Sqlite
```

Rollback limits: code-only rollbacks keep the three tables in place, but migrating `Down` past
the shared-tables migration deletes `service_installations` and `service_audit_logs` with their
data — the binding table is untouched, yet a backup is still mandatory, `Down` must only ever be
rehearsed on an isolated copy, and a completed installation must never be restored to `Pending`
by re-importing a dropped row. This stage deliberately does not open the first-installation
(Setup) flow.

## Configuration

| Key | Meaning |
| --- | --- |
| `ReferenceBff:Authority` | SignaCore base address (HTTPS) |
| `ReferenceBff:ClientId` | Client id registered in SignaCore |
| `ReferenceBff:ClientSecret` | Client secret — inject through the environment or user secrets |
| `ReferenceBff:RedirectUri` | This host's HTTPS redirect URI (default path `/signin-oidc`) |
| `ReferenceBff:Scope` | Requested scope (must contain `openid`) |

The configuration is validated at startup; an incomplete configuration fails to start.

Register the redirect URI on the SignaCore application (interactive OIDC configuration) with the
code flow enabled before using the sample.

## Run

```bash
SIGNACORE_REFERENCE_BFF_CLIENT_SECRET=... \
dotnet run --project samples/SignaCore.ReferenceBff \
  --ReferenceBff:Authority=https://your-signacore-host \
  --ReferenceBff:ClientId=reference-bff \
  --ReferenceBff:RedirectUri=https://your-bff-host/signin-oidc
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

## Scope

This is a sample consumer of SignaCore, not a product. The ticket store is single-instance
memory, coordinated upstream logout and the runtime use of the administrator binding are out of
scope, and deployment hardening beyond the boundaries above is intentionally left out.
