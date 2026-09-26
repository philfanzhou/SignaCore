# Management bearer session schema

The [management bearer model in issue #360](https://github.com/philfanzhou/SignaCore/issues/360)
is the authority for credentials, lifecycle, trust boundaries, and activation stages.
This document covers the additive schema delivered by
[task #382](https://github.com/philfanzhou/SignaCore/issues/382), the lifecycle service, and the
authentication scheme.

## Persistence contract

`management_bearer_sessions` stores a GUID primary key, a required unique `token_digest`
(maximum and checked length 71), and a required `account_id` reference to `accounts(id)`
with `ON DELETE CASCADE`. It has required `created_at` and `expires_at` instants and nullable
`revoked_at`. Indexes support digest lookup, account lookup, and expiry cleanup.

Checks enforce `expires_at > created_at` and either no revocation instant or
`revoked_at >= created_at`. Instants use the existing `ConfigureInstant` mapping:
PostgreSQL `timestamptz` and SQLite integer Unix microseconds. No plaintext credential,
password, application secret, username, or permission cache is stored in this table.

The database checks length and temporal ordering. It does not validate a digest prefix or
hexadecimal alphabet, enforce the future 15-minute lifetime, or authenticate a bearer.
Lifecycle services will enforce those rules as defined by the authoritative model.
There is no new handler, writer, route, DI registration, setting, or frontend activation in
this schema delivery. Existing Cookie, OIDC, and business JWT behavior is unchanged.

## Lifecycle service

[Task #383](https://github.com/philfanzhou/SignaCore/issues/383) adds an internal
`ManagementBearerSessionService` that issues, validates, revokes, and cleans up these rows.
Each operation uses its own non-retrying `IdentityDbContext`; `CleanupWorker` deletes rows
expired for at least 24 hours in batches of at most 1000. Its contract suite is
`ManagementBearerSessionDatabaseContractTests`.

## Authentication scheme

[Task #384](https://github.com/philfanzhou/SignaCore/issues/384) adds the management bearer
authentication scheme. Credentials are issued and revoked by the explicit entries described in
[Issuing and revoking a credential](#issuing-and-revoking-a-credential); the built-in admin console
still signs in with the cookie until [#385](https://github.com/philfanzhou/SignaCore/issues/385).

The host's default authenticate, challenge, and forbid scheme is a selector:

- A request whose path is under `/api/admin` or `/management/v1` **and** that carries an
  `Authorization` header — any value, including an empty value or several values — is
  authenticated by the management bearer only. The management cookie is not consulted, so a
  rejected header is never rescued by a valid cookie.
- Every other request uses the shared ServiceMantle management cookie exactly as before. Sign-in and
  sign-out always use the cookie.

The bearer accepts exactly one `Authorization: Bearer <credential>` value and validates it live on
every request: revocation, expiry, account activity, and whether the account is still the
configured bootstrap administrator. A valid credential produces the same operator identity as a
cookie login, so `/api/admin/session/me` and audit operators do not change. Any rejection answers
`401` with `Cache-Control: no-store` and `{"errorCode":"management.bearer.unauthenticated"}`; a
database that cannot answer yields `503` with `{"errorCode":"management.bearer.unavailable"}`.
Neither response echoes the header, and no log, audit row, or metric carries the credential.

These routes stay cookie-only and ignore the `Authorization` header entirely: the shared
`/management/v1/session` entries, `PUT /management/v1/bootstrap`, `GET /api/admin/bootstrap`, and
`POST /api/admin/bootstrap/test`. ServiceMantle pins the bootstrap update to the local management
cookie, so bootstrap editing is not available with a bearer. The business JWT (`/api/profile/*`),
OIDC (`/oauth2/*`), and gateway routes keep their own schemes and reject a management bearer.

A reverse proxy in front of SignaCore must not add or forward an `Authorization` header to
`/api/admin` or `/management/v1` for cookie-based console users: such requests are now authenticated
by the bearer and answer `401`. Rolling back the code restores cookie-only management
authentication; there is no data change.

`ManagementBearerAuthenticationTests` covers the route matrix, strict dispatch with server-injected
header forms, the `503` mapping, caller cancellation, the ServiceMantle startup constraint, and a
sensitive-carrier scan. `ManagementBearerAuthenticationDatabaseContractTests` shows a revocation on
one PostgreSQL replica rejecting the next authentication on another.

## Issuing and revoking a credential

[Task #392](https://github.com/philfanzhou/SignaCore/issues/392) adds two entries for explicit
bearer clients. Both are served only once the service is ready and are same-origin management
operations.

### `POST /api/admin/session/bearer/login`

Request: `Content-Type: application/json` (an optional `charset` must be `utf-8`), exactly one
`X-ServiceMantle-Request: 1` header, no query string, no `Content-Encoding`, and a body of at most
64 KiB (declared or chunked) shaped `{"username":"...","password":"..."}`. Other JSON properties are
ignored.

The entry is anonymous and ignores any `Authorization` header or management cookie sent with it; it
never sets or renews a cookie. The credentials go through the same chain as the shared cookie login
(`/management/v1/session/login`): the same password validator, the same bootstrap administrator
restriction, and the same login attempt and audit records. It shares that login's setup rate limit
budget (five attempts per sliding window per client address across both entries) and its 10 second
budget.

| Outcome | Response (all with `Cache-Control: no-store`, `application/json`) |
| --- | --- |
| Issued | `200 {"tokenType":"Bearer","accessToken":"...","expiresAtUtc":"..."}`; the credential is valid for 15 minutes |
| Missing or wrong `X-ServiceMantle-Request`, other media type or charset, query string, `Content-Encoding`, oversized body, malformed JSON, or a non-string `username`/`password` | `400 {"errorCode":"management.request.invalid"}`, before any authentication |
| Wrong password, unknown user, disabled account, or an account that is not the bootstrap administrator (indistinguishable) | `401 {"errorCode":"management.session.unauthenticated"}` without `WWW-Authenticate` |
| Identity provider failure, credential storage failure, or the 10 second budget exceeded | `503 {"errorCode":"management.session.unavailable"}`; no credential is returned |
| Rate limit exceeded | `429` |

Unlike the cookie login, a malformed JSON body is a `400` rather than a `401`. A caller that cancels
the request never receives a credential; if the row was already committed it simply expires. A
successful authentication is recorded as `login_success` even when issuing then fails.

### `POST /api/admin/session/bearer/logout`

Authenticated by the management bearer scheme alone (the `ManagementBearer` policy): a request
without an `Authorization` header — for example one carrying only the management cookie — answers
the bearer scheme's `401 {"errorCode":"management.bearer.unauthenticated"}` and leaves the cookie
session untouched. It requires exactly one `X-ServiceMantle-Request: 1` header (checked before
anything is revoked) and uses the management rate limit. It revokes exactly the credential in the
`Authorization` header; a query string or body never supplies one.

| Outcome | Response |
| --- | --- |
| Revoked | `204`, empty body, `Cache-Control: no-store` |
| Missing or wrong `X-ServiceMantle-Request` | `400 {"errorCode":"management.request.invalid"}`; nothing is revoked |
| Unknown, expired, or already revoked credential (including a concurrent logout of the same credential) | `401 {"errorCode":"management.bearer.unauthenticated"}` with `WWW-Authenticate: Bearer` |
| Credential storage unavailable | `503 {"errorCode":"management.bearer.unavailable"}` |

Revocation is a single conditional update, so of two concurrent logouts of one credential exactly
one answers `204`. A revoked credential is rejected by the next authentication on every replica
sharing the database; requests already authorized are not interrupted.

### Transport and client responsibilities

Over plain HTTP the password and the credential travel in clear text; serve these entries over
HTTPS or behind a TLS-terminating proxy. Keep the credential in memory only, send it only to the
same origin, and discard it locally when logout fails. The password is only passed to the
validator and the credential appears only in the `200` login body; neither reaches a URL, log,
exception, trace, metric, or audit record.

### Rolling back the entries

Stop routing clients to the two entries, revoke every outstanding credential (for example
`UPDATE management_bearer_sessions SET revoked_at = <now UTC> WHERE revoked_at IS NULL`), and then
roll back all replicas together. The table can stay in place.

`ManagementBearerSessionEndpointTests` covers the success path, every malformed-request shape, the
indistinguishable `401`, the shared setup budget, storage failure, the budget timeout, caller
cancellation, the logout matrix, concurrent revocation, and a sensitive-carrier scan with a
negative self-check. `ManagementBearerSessionEndpointDatabaseContractTests` logs in on one
PostgreSQL replica, uses and revokes the credential on another, and sees the first replica reject
it.

## Upgrade and rollback

Apply the provider's incremental `AddManagementBearerSessions` migration through the
existing deployment migration procedure, with the deployment owner's backup policy.
New installations and upgrades get an empty table. The migration creates only this table
and its indexes; existing account, application, identity session, token, settings,
installation, audit, and data-protection data are retained.

Reverting application code can leave the unused table in place. `Down` to the **direct
predecessor** drops only `management_bearer_sessions`, including its indexes, checks, and
foreign key, and permanently removes its short-lived session rows. After writers are
introduced, stop all writers before running `Down`. Do not cross older irreversible
retirement migrations. Reapplying `Up` creates an empty table again.

After interrupted or failed DDL, inspect the actual migration history and physical schema
before retrying or rolling back. Cancellation does not promise to undo a migration that
has already committed. The deployment owner is responsible for recovery and backups.

## Executable evidence

`ManagementBearerSessionSchemaDatabaseContractTests` runs the same three scenarios against
SQLite and a real PostgreSQL container:

- Fresh physical schema, model/snapshot parity, microsecond UTC round trips, nullable and
  non-null revocation, unique digest and primary key, orphan account and invalid value
  rejection, transaction rollback, and account deletion that cascades only its own sessions.
- A populated direct-predecessor database, fault and caller cancellation after DDL executes,
  observed history/schema recovery, upgrade, `Down`, and re-upgrade, comparing existing
  schema and complete row hashes at each boundary.
- Two independently opened connections competing for the same digest: exactly one insert
  succeeds and one row remains. This does not extend SQLite's supported deployment topology.

Run both providers (Docker required):

```bash
RUN_SIGNACORE_DATABASE_CONTRACTS=true dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj -c Release --filter FullyQualifiedName~ManagementBearerSessionSchemaDatabaseContractTests
```

The existing CI Database Contract Matrix selects this class through its
`DatabaseContractTests` name and enables PostgreSQL. Without the environment gate,
PostgreSQL cases are skipped; that run alone is not full schema acceptance.
