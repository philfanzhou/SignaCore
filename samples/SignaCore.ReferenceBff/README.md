# SignaCore Reference BFF

A minimal reference Browser-for-Frontend (BFF) that signs administrators in to a SignaCore
server through Authorization Code + PKCE (S256), keeps every token in a server-side session, and
exposes only an opaque local cookie to the browser.

The sample resolves the authorization, token, JWKS, and UserInfo endpoints from the Authority's
OpenID Connect Discovery document. Nothing is hardcoded.

> **Single-instance reference.** The session ticket store is in-process memory: a restart loses
> sessions and replicas do not share them. Replace it with a shared store before running more
> than one instance. Coordinated upstream logout is delivered by a later SignaCore task.
>
> **Runtime authorization over an optional local database.** The sample's sign-in keeps working
> with no database at all; `GET /bff/admin` additionally enforces the local administrator
> binding through the optional `ReferenceBffDatabase` configuration below. The BFF-owned storage
> lives in `samples/SignaCore.ReferenceBff.Database` (with its SQLite migration project
> `samples/SignaCore.ReferenceBff.Database.Migrations.Sqlite`) and carries four tables: the
> single initial-administrator binding slot (`management_role_bindings`, staging and exact-match
> read via `ManagementRoleBindingStore`) and the shared ServiceMantle tables
> (`service_installations`, `service_audit_logs` and `service_data_protection_keys`) mapped through the pinned
> `ServiceMantle.Persistence.EntityFrameworkCore` package — never a local clone of a shared
> entity. The BFF's fixed ServiceMantle service id is `reference-bff`, not the product's
> `signacore`. Nothing migrates or binds automatically at runtime. Setup requires an explicit
> local code command followed by authenticated HTTP completion.

## From an empty installation to the first administrator

Use .NET 10, the .NET 10 `dotnet-ef` tool
(`dotnet tool install --global dotnet-ef --version 10.0.0`), and two reachable HTTPS origins with certificates trusted by both the browser and the BFF. Use an empty SignaCore
database and a **separate** empty BFF database. Run commands from the repository root. Values in
angle brackets below are placeholders; supply secrets through your protected environment, not
shell history, command arguments, source control, or captured output.

Follow this order; an installed SignaCore administrator and a BFF administrator are separate roles:

1. Install and start SignaCore using [First-Run Setup](../../docs/development/FirstRunSetup.md)
   and the [deployment guide](../../docs/development/Deployment.md). Complete bootstrap configuration
   and `/setup`, then restart as instructed there. Configure its public HTTPS origin to match the
   BFF's Authority. Do not use the BFF's local Setup Code for SignaCore setup.
2. Open SignaCore's `/admin` console and sign in as the administrator created during installation.
   The application and account API operations below require the `AdminSession` policy; an
   application secret or an end-user access token does not authorize them. Use the console's
   application and account pages, or the API entries listed below. The
   [application-management specification](../../docs/modules/Admin/AppManagement/02-SPEC.md) and
   [account-management specification](../../docs/modules/Admin/UserManagement/02-SPEC.md) describe
   those administration boundaries, including the management-session login entry.
3. In **Applications**, create a **Confidential** application (`POST /api/admin/apps`, body
   `{"appName":"Reference BFF","callbackUrl":null,"ttlSeconds":0,"clientType":"Confidential"}`).
   Save the returned `appId` as `ReferenceBff__ClientId` and the **one-time** `appSecret` as
   `ReferenceBff__ClientSecret` in your protected environment. The secret cannot be read again.
   A claims callback is unrelated to the OIDC redirect URI; leave it empty for this sample.
4. Set the application's audience mode to **PerApplication** using
   `PUT /api/admin/apps/{appId}/audience-mode` with `{"mode":"PerApplication"}`.
5. Register the BFF's exact HTTPS callback using
   `POST /api/admin/apps/{appId}/oidc/redirect-uris` with
   `{"kind":"Redirect","uris":["https://<bff-host>/signin-oidc"]}`. Set the same URI in
   `ReferenceBff__RedirectUri`. See [Interactive Client Model](../../docs/oidc/ClientModel.md)
   for the audience and redirect-registration contract; its target-design label does not enable
   future public-client or logout capabilities in this sample.
6. Enable the application's interactive policy using
   `PUT /api/admin/apps/{appId}/oidc-policy` with
   `{"clientType":"Confidential","allowAuthorizationCode":true,"allowedScopes":["openid","profile"],"allowRefreshToken":false,"identitySessionMaxAgeSeconds":null}`.
   **Steps 4 and 5 must precede this step.** A new application defaults to `Shared`; enabling
   code flow then fails with `Authorization Code flow requires a per-application audience.`
   With `PerApplication` but no redirect registration it fails with
   `Authorization Code flow requires at least one redirect URI.` Neither failure repairs the
   configuration automatically.
7. In **Users**, create an active password account for the person who will become the BFF
   administrator (`POST /api/admin/users`, body
   `{"username":"<account-name>","password":"<injected-password>","displayName":null,"remark":null,"nickname":null}`).
   Enter that account's credentials only on SignaCore's login page; local BFF authorization is
   established by the next step, not by its SignaCore administrator status.
8. Follow [Configuration](#configuration) to migrate the BFF database, using the **same**
   `ReferenceBffDatabase__ConnectionString` for migration, the code command, and the Web host.
   Inject all three `ReferenceBffDatabase__*` values and follow
   [Local Setup Code](#local-setup-code-operations-phase) to run `--setup-code create` in a protected
   interactive terminal. [Start the BFF](#run), open `/bff/login`, and sign in as the account from
   step 7. Open `/bff/setup` and submit the locally displayed code as described in
   [First administrator over HTTP](#first-administrator-over-http). A successful submission returns
   `204`; `/bff/admin` then returns `200 {"isAdministrator":true}` for that same identity.

## Ownership boundaries

| Capability / decision | Owner | Consumer responsibility |
| --- | --- | --- |
| Credentials, authentication, Discovery, OIDC, JWT signing/JWKS and UserInfo | SignaCore | BFF validates the protocol and keeps tokens server-side; it never handles the account password. |
| Installation state and Setup Code lifecycle, common management HTTP gates | ServiceMantle | BFF supplies its service id, database context, and first-administrator contributor. |
| Management audit persistence, sensitive-header registry and structured-log sanitization/Console host | ServiceMantle | BFF emits bounded events and registers its CSRF header; it does not copy shared algorithms or storage. |
| Encrypted Data Protection key-ring persistence | ServiceMantle (framework owns key lifetimes) | BFF supplies its independent database and external root key; see the existing upgrade section below. |
| Local role binding and each administrator authorization decision | BFF | Match the verified issuer/subject to the active local binding after current UserInfo confirmation. SignaCore does not assign this role. |
| Browser session and local logout | BFF / ASP.NET Core | Keep tokens in the single-instance ticket store and enforce antiforgery on logout. |

The authoritative state/recovery model remains [#74](https://github.com/philfanzhou/SignaCore/issues/74),
and the first-release boundary remains [#47](https://github.com/philfanzhou/SignaCore/issues/47).
The centralized shared-wiring tests assert both effective registrations and ServiceMantle assembly
provenance; their negative controls deliberately replace a store/provider or remove a required
policy and require the same acceptance assertion to fail. This proves consumer wiring, not the
correctness of every shared-library algorithm.

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
  are staged is refused. HTTP completion uses validate → orchestrate → stage-consume → one save
  → commit; it never calls this initialization entry.

Apply each provider's own migrations explicitly before running anything against this database
(the commands are in the Configuration section below); nothing migrates or seeds automatically
at startup. Rollback limits: code-only rollbacks keep the four tables in place, but migrating
`Down` past the shared-tables migration deletes `service_installations` and `service_audit_logs`
with their data — the binding table is untouched, yet a backup is still mandatory, `Down` must
only ever be rehearsed on an isolated copy, and a completed installation must never be restored
to `Pending` by re-importing a dropped row.

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
| `ReferenceBffDatabase:DataProtectionRootKey` | External key-ring root key; inject only through a protected environment |

The configuration is validated at startup; an incomplete configuration fails to start. The three
`ReferenceBffDatabase` keys must be provided together, and a partial or unknown combination fails
startup with a fixed message that echoes no value. With all three omitted, the sample runs exactly its
login-only shape and every authenticated management query answers a fixed `503`.

Before first use, provision `ReferenceBffDatabase__ConnectionString` through the protected
environment, then run **one** command matching your provider below. Both design-time factories read
that variable; do not rely on their fallback database names. Keep the same value for the code command
and Web host. The runtime never migrates, creates schema, or seeds:

```bash
# PostgreSQL
dotnet ef database update --project samples/SignaCore.ReferenceBff.Database \
  --startup-project samples/SignaCore.ReferenceBff.Database

# SQLite
dotnet ef database update --project samples/SignaCore.ReferenceBff.Database.Migrations.Sqlite \
  --startup-project samples/SignaCore.ReferenceBff.Database.Migrations.Sqlite
```

### Persistent Data Protection and upgrades

With database configuration present, the shared ServiceMantle repository stores the ASP.NET Core
Data Protection key ring under `reference-bff`. Key and revocation XML are authenticated `sm:v1:`
envelopes; each repository call owns a separate context and transaction and cannot commit Setup's
unit of work. The framework continues to own key lifetimes. With no database configuration, the
framework's default key storage is unchanged.

For an existing deployment, stop the BFF, back up its database, run the provider-specific
`dotnet ef database update` command above to apply `AddSharedDataProtectionKeys`, provision a strong
root key through `ReferenceBffDatabase__DataProtectionRootKey`, and then restart. Keep that key stable
and protect its backup. Never put it in command arguments, appsettings files, logs, or source control.
The previous framework key ring is not imported: existing protected browser state must be renewed
on this upgrade. Subsequent restarts with the same root key reuse the stored ring; antiforgery data
remains decryptable, but in-memory sessions and in-flight OIDC state still do not survive restart.
Missing schema, an unreachable database, a wrong root key or damaged ciphertext fail closed at
startup or first key use; the repository never falls back to local files.

A code rollback preserves the new table and data. On an isolated backup copy only, migrating to
`AddSharedInstallationAndAudit` removes **only** `service_data_protection_keys`. This destroys the
key ring and invalidates existing antiforgery/correlation cookies; it is not a recovery procedure.
Root key distribution, rotation and recovery, multi-instance coordination and shared session stores
remain operator responsibilities outside this single-instance sample.

An empty migrated database denies management (`403`); a missing schema or an unreachable database
fails closed without ever widening permission (key use can fail before a management response).

## Local Setup Code (operations phase)

After explicitly migrating the independent BFF database above, inject
`ReferenceBffDatabase__Provider` (`SQLite` or `PostgreSQL`),
`ReferenceBffDatabase__ConnectionString` and `ReferenceBffDatabase__DataProtectionRootKey` through your protected environment. In a protected local
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

The command exits without starting HTTP or binding an administrator. Start the normal Web host
after `create`, then complete the HTTP flow below. Protect database access and the terminal,
and use TLS for HTTP.
The command does not protect against terminal recording, an OS administrator or process-memory
inspection, and does not promise cross-process exactly-once delivery.

## First administrator over HTTP

With database configuration present, the sample consumes `ServiceMantle.AspNetCore` at the
existing pinned version and uses its composed pipeline and code-only Setup entries. Without
that configuration, the original login sample remains available and Setup is not mapped.
The Web host never migrates, creates an installation row, or issues a code. A missing schema,
missing installation, corrupt state, or unavailable database returns 503. Run the local `create`
command before attempting to sign in to a configured BFF.

Open `/bff/setup`, sign in through the normal OIDC challenge, and enter the locally issued code.
The form posts only `{ "code": "..." }` to `POST /management/v1/setup`, with
`X-ServiceMantle-Request: 1` and the cookie-bound `X-ReferenceBff-CSRF` token. The shared parser
limits JSON to 4 KiB; identity, role, duplicate fields, and extra input are rejected. The
configured OIDC callback must not conflict with `/`, `/error`, `/bff`, or `/management` routes.
Existing login, callback, diagnostics, profile, local logout and admin reads remain admitted in
Pending and Completed; local administrator authorization is still required for `/bff/admin`.

The authoritative BFF state model and failure boundaries are maintained in
[the BFF tracker](https://github.com/philfanzhou/SignaCore/issues/74). Completion checks the code,
reconfirms the ticket's verified issuer/subject through current UserInfo, and stages the first
active binding and an opaque shared audit in a fresh scoped serializable transaction. Shared
code consumption revalidates the code before one save and commit. PostgreSQL locks only the
`reference-bff` installation; SQLite uses its single writer. There is no automatic retry.
Only successful commit and scope cleanup allow 204. Then `/bff/admin` returns 200 for that identity.
Neither an inactive slot nor a Completed installation can be claimed again.

`GET`/`HEAD /management/v1/setup` reports persisted installation status. Completed POST replay
returns 409 before reading the body. Unauthenticated or invalid/expired-code attempts return
401; malformed input or failed CSRF returns 400; an unavailable authority or persistence
boundary returns 503. Session-invalid identity checks clear the local ticket, while dependency
failures preserve it. Shared phase, sensitive-header and rate-limit protections run before
completion; exhausted Setup quota returns 429. Failure responses carry no identity or code.
A precommit failure rolls the whole attempt back. Cancellation, cleanup failure or lost
acknowledgement after commit does not undo installation; check persisted status before recovery.
Code rollback preserves committed data and must never reset Completed to Pending.

## Run

Complete the ordered SignaCore registration above. Inject `ReferenceBff__Authority`,
`ReferenceBff__ClientId`, `ReferenceBff__ClientSecret`, `ReferenceBff__RedirectUri`, and
`ReferenceBff__Scope` (`openid profile`) through your protected environment. For the database-enabled
flow also inject the three `ReferenceBffDatabase__*` keys from [Configuration](#configuration),
apply migrations and create the local code before starting. Root-key requirements and upgrade
behavior are defined only in [Persistent Data Protection and upgrades](#persistent-data-protection-and-upgrades).
Configure a trusted HTTPS listener (or TLS proxy) for the registered BFF origin, then run:

```bash
dotnet run --project samples/SignaCore.ReferenceBff --no-launch-profile
```

Open `https://<bff-host>/bff/login`, then complete `/bff/setup` and check `/bff/admin` as described
above. The SignaCore Authority must also be reachable over trusted HTTPS from the BFF process.

## Structured logs

Every Web host uses the pinned `ServiceMantle.Serilog` Console pipeline, with service identity
`reference-bff` and instance identity `reference-bff-local`. BFF-owned startup, login, UserInfo,
authorization, Setup and logout events use `ServiceLogContext` scopes containing `ServiceName`,
`ServiceVersion` and `InstanceId`. Only finite `Operation` and `Outcome` fields enter those scopes:
the shared `StructuredLogSanitizer` drops unlisted fields and headers before any logger sees them.
The shared host independently sanitizes structured output properties. No request bodies, identities,
exception details, tokens, setup codes, cookies, credentials or connection values are BFF log fields.
Cancellation is observed before emitting a result, so abandoned requests emit no successful result.

The same logging registration runs with or without a local database; it adds no HTTP middleware,
headers or endpoints. The optional Setup pipeline still owns the shared sensitive-header registry,
including `X-ReferenceBff-CSRF`. The local `--setup-code create|rotate` branch returns before building
a Web or logging host: its protected terminal display and fixed error categories are unchanged.

Operational options can be supplied through the existing configuration providers under
`Logging:ServiceMantle`: `MinimumLevel` defaults to `Information`, `IncludeScopes` to `true`, and
`FlushTimeout` to `00:00:02`. Keep scopes enabled to include the identity and operation fields.
No business settings or secrets belong in these options. This sample adds no remote sink or logging
store. Protect collected logs and their retention/access policy; third-party free-text messages and
external collectors are outside the BFF-owned event guarantee. A code rollback restores the previous
logging behavior without a schema, data, token or HTTP migration.

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
- `POST /bff/logout` is protected by antiforgery and clears the local cookie and server-side
  ticket. There is no GET logout. The optional Setup POST has the separate protections described
  in [First administrator over HTTP](#first-administrator-over-http).
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

## Verify the sample

With Docker available, run the complete suite (including both database providers) from the root:

```bash
RUN_SIGNACORE_DATABASE_CONTRACTS=true dotnet test \
  tests/SignaCore.ReferenceBff.Tests/SignaCore.ReferenceBff.Tests.csproj --configuration Release
```

`Readme_InstalledSignaCoreThenAdminApisLoginAndSetupCompleteInOrder` exercises the registration
order, both premature-enable failures, and the login → Setup → administrator success path against
the real SignaCore host. `SharedWiring_*` centralizes provenance checks and negative controls for
installation state, Setup Code, audit, key-ring options, sensitive headers, and logging.
The canary tests cover controlled Console output, browser bodies/headers/URLs, every bounded error
reason, Setup audit columns, and command stdout/stderr. Session-cookie issuance at the login callback
and form antiforgery tokens are intentional browser outputs; the session-cookie value must not be
reflected by later pages. Canary assertion failures name only the carrier, never the sensitive value.
These checks retain the single-instance and controlled-output limits documented above.

### Two upstream SignaCore hosts

```sh
dotnet test tests/SignaCore.ReferenceBff.Tests/SignaCore.ReferenceBff.Tests.csproj -c Release --filter FullyQualifiedName~ReferenceBffMultiInstanceTests
```

This normal-path acceptance keeps **one BFF and one in-memory ticket store**. Two independent
SignaCore hosts share the installed database, bootstrap, signing material and Data Protection
key ring. Explicit test transports send the password login and code exchange to A, authorization,
Discovery/JWKS and UserInfo to B, then swap A/B and repeat the session-reuse flow twice in each
direction. It checks both token signatures, matching subjects, audience rejection, and the local
403-before-binding / 200-after-binding decision. A separate aborted UserInfo request exercises
cancellation and fixture cleanup. These tests do not certify a multi-instance BFF, PostgreSQL
atomic races, or the AC-13 production activation gate.

The [canonical model](../../docs/oidc/CanonicalSemanticModel.md) remains the protocol authority.
The finite output checks use these carrier-specific rules:

| Carrier | Scan boundary and required protocol output |
| --- | --- |
| BFF-owned logs | A tee for the exact `BffOperationLog` emitter captures every complete message, scope/state property and exception before forwarding unchanged to the shared Console pipeline. Expected operation/outcome events must exist. Injected message/property/exception canaries must fail the same scanner. Events are never selected by canary content. |
| Final `/`, `/bff/me`, `/bff/admin`, `/bff/diagnostics` | Body, headers and URL exclude credentials, code/verifier, tokens, cookies, state and nonce. Only the exact home-form CSRF value is required in its hidden field, with its antiforgery cookie in Set-Cookie. |
| Login challenge | State, nonce and PKCE challenge are required only in their named Location query fields. OIDC nonce/correlation cookies are required only in their Set-Cookie carrier. |
| Callback | Code/state are necessary callback request query inputs; the server-side-ticket session cookie and OIDC-cookie deletion are necessary Set-Cookie outputs. Later display pages may not reflect those values. |

No global canary allowlist is used. Failure artifacts report safe stages/results, never raw
Console output, protocol URLs or credential values. The existing `ReferenceBffLoggingTests`
controlled-output regressions still run unchanged; arbitrary third-party Console text and external
collectors remain outside the BFF-owned log guarantee. CI Build & Test runs this test assembly.

## Scope

This is a sample consumer of SignaCore, not a product. The ticket store is single-instance
memory; coordinated upstream logout, multiple administrators, role CRUD, and deployment
hardening beyond the boundaries above are intentionally left out. This is not a production
administrator console.
