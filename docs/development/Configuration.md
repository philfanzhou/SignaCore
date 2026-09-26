# Configuration Reference

SignaCore keeps global application configuration in the business database, in the shared
`service_settings` aggregate. Every instance therefore reads the same active configuration, changes
are transactional and audited, and there is no per-instance configuration drift. The legacy
`system_settings` table has been removed by the guarded `RetireSystemSettings` drop; the admin
console reads and writes the shared
aggregate through the shared management setting endpoints (`GET /management/v1/settings`,
`GET /management/v1/settings/definitions`, and `POST /management/v1/settings`). A deployment that
predates the aggregate is upgraded into it once — straight from the deployment configuration by
the protected legacy import — inside
the startup initialization lock. See
[Shared settings stack](SharedSettings.md).

Only two things cannot live there, because they are required to open and decrypt that database:

1. the database provider, server version, and connection string;
2. the external root key used to decrypt protected values.

Those live in one small, writable bootstrap file. See [Bootstrap file](#bootstrap-file).

Precedence for the remaining keys is: database snapshot (authoritative), then command line,
environment variables, environment-specific appsettings, and `appsettings.json`. Environment
variables use ASP.NET Core double-underscore nesting. Deployment-provided values for
database-backed keys are ignored and logged as legacy overrides at startup; remove them from your
launcher.

## Bootstrap file

The production path is fixed and needs no additional environment variable:

- published application: `<application-base>/config/signacore.bootstrap.json`
- container: `/app/config/signacore.bootstrap.json`

For Docker, mount a persistent host directory read-write at `/app/config`. SignaCore creates or
atomically replaces the file from the protected bootstrap and administration workflows. The mutable
`/app/data` mount remains available for other runtime data but is not a configuration authority.

The canonical and complete schema is:

```json
{
  "FormatVersion": 1,
  "ServiceId": "signacore",
  "Database": {
    "Provider": "PostgreSQL",
    "ServerVersion": "15",
    "ConnectionString": "Host=db;Database=signacore;Username=signacore;Password=replace-me"
  },
  "MasterKey": "a-long-random-secret"
}
```

Rules:

- no fields other than `FormatVersion`, `ServiceId`, `Database.Provider`,
  `Database.ServerVersion`, `Database.ConnectionString`, and inline `MasterKey` are accepted;
- the file lifecycle (locate, parse, atomic create/replace, private permissions) is owned by the
  shared ServiceMantle bootstrap file store. `FormatVersion` is the store's format marker (always
  `1` when SignaCore writes) and `ServiceId` binds the file to this service (`signacore`); files
  written before those fields existed are still read, and the canonical form is restored on the
  next replacement. A `Database.ServerVersion` of `null` is omitted rather than written;
- the whole file is a secret and must be readable and writable only by the SignaCore runtime
  identity (`chmod 600` on Unix-like hosts; directories the store creates are `chmod 700`);
- creation never overwrites an existing file; writes use a flushed temporary file in the same
  directory followed by an atomic publish (hard link for creation, `File.Replace` for updates);
- the directory must live on persistent storage and be backed up with the business database.

Neither value is ever logged. Startup diagnostics report the provider and the database host only.

A missing file starts protected Bootstrap Configuration Mode: liveness remains true, readiness is
false, normal APIs return `503 bootstrap_configuration_required`, and `/bootstrap` requires the
one-time code printed to standard output. A present but unreadable or malformed file is a fatal
startup error whose message names the expected path without disclosing secrets. Development falls
back to a `Database` section in `appsettings.Development.json` when the file is absent. Create that
ignored local file from the tracked `appsettings.Development.example.json`; the fallback is refused
outside Development.

`Bootstrap:FilePath` may point at an equivalent file elsewhere. It exists for tests and for
orchestrators that mount secrets at a non-default path; production deployments do not need it.

## First-run setup

A new, empty database starts in Setup Mode. See [First-run setup](./FirstRunSetup.md).

## Database-backed settings

These keys are owned by the shared `service_settings` aggregate (normalized keys; see
[Shared settings stack](SharedSettings.md)). Defaults are the safe product defaults used to seed a
new installation, and live in versioned application code.

### Public identity

| Key | Default | Notes |
| --- | --- | --- |
| `Endpoints:PublicBaseUrl` | collected by setup | Canonical base URL used to build discovery endpoints. Must be HTTPS unless the operator explicitly opts in to HTTP |
| `Jwt:Issuer` | collected by setup | Initialized to the normalized public base URL; must keep matching it |
| `Jwt:Audience` | `SignaCore.Services` | Must match downstream validation |
| `Jwt:TokenExpirationHours` | `2` | Access-token lifetime, 1–24 |
| `RefreshToken:ExpirationDays` | `7` | Refresh-token lifetime, 1–365 |
| `PasswordHasher:WorkFactor` | `11` | BCrypt work factor, 10–15 |
| `Security:AllowNonHttpsIssuer` | `false` | Explicit insecure-transport opt-in; no IP/host/network-zone inference |

### Administrative console

| Key | Default | Notes |
| --- | --- | --- |
| `Admin:Username` | collected by setup | Username of the administrator account created by first-run setup. Only this account may sign in to the console |
| `AdminWeb:AllowedOrigins` | `[]` | Setup seeds the public base URL. Production admin cookies are always `Secure` |

### Reverse proxy

| Key | Default | Notes |
| --- | --- | --- |
| `ReverseProxy:KnownProxies` | `[]` | When TLS terminates at a proxy, add each proxy IP. Untrusted `X-Forwarded-*` headers are ignored |

### Callback security

| Key | Default | Notes |
| --- | --- | --- |
| `Callback:AllowedDomains` | `[]` | Explicit allowlist, preferred over relying on address filtering alone |
| `Callback:AllowPrivateAddresses` | `false` | |
| `Callback:RequireHttps` | `true` | |

Callback connections reject local, private, link-local, multicast, reserved, and cloud metadata
address ranges. The address is checked in the actual TCP connection path to prevent DNS rebinding
between validation and connection. Redirects are not followed, and system HTTP proxies are bypassed
so the checked endpoint is the endpoint actually reached. Enable private or plain-HTTP callbacks only
for a deliberately isolated internal deployment.

### SMS

| Key | Default | Secret | Notes |
| --- | --- | --- | --- |
| `Sms:OtpTtlSeconds` | `300` | | 60–900 |
| `Sms:MaxAttempts` | `5` | | 1–10 |
| `Sms:LockoutSeconds` | `600` | | 60–86400 |
| `Sms:MinSendIntervalSeconds` | `60` | | 30–3600 |
| `Sms:MaxSendsPerHour` | `5` | | 1–100 |
| `Sms:MaxSendsPerDay` | `10` | | Must be ≥ `MaxSendsPerHour` |
| `Sms:OtpHmacKey` | empty | yes | Base64, at least 32 bytes, required once any profile exists |
| `Sms:BypassCode` | empty | yes | Disabled when empty |
| `Sms:BypassPhones` | `[]` | | Empty disables the bypass even when a code is configured |
| `Sms:Profiles` | `{}` | yes | Per-profile provider credentials; optional when only the bypass allow-list is used |

A profile is required only to deliver codes. A deployment that enables SMS login purely for testing can
leave `Sms:Profiles` (and therefore `Sms:OtpHmacKey`) empty, set `Sms:BypassCode` plus `Sms:BypassPhones`,
and leave the per-application SMS provider profile unset; the listed phones then log in with the fixed
code, while `POST /api/auth/sms-code` answers that no provider is configured.

### WeChat

| Key | Default | Secret | Notes |
| --- | --- | --- | --- |
| `WeChat:AppId` | empty | | Required before any application may leave `wechat_login_mode = Disabled` |
| `WeChat:AppSecret` | empty | yes | Must be set together with `WeChat:AppId` |
| `WeChat:ApiBaseUrl` | `https://api.weixin.qq.com` | | Must be https, except for a loopback stub |

Startup fails when only one of `WeChat:AppId` / `WeChat:AppSecret` is present. When both are absent,
WeChat login stays unavailable and the admin API refuses to enable a WeChat mode, instead of issuing
requests to WeChat with an empty appid.

### LDAP

| Key | Default | Secret |
| --- | --- | --- |
| `Ldap:Enabled` | `false` | |
| `Ldap:DefaultDirectoryKey` | empty | |
| `Ldap:MaxConcurrentOperations` | `20` | |
| `Ldap:Directories` | `[]` | yes (entries carry bind passwords) |

### Observability

| Key | Default | Secret | Notes |
| --- | --- | --- | --- |
| `Loki:Uri` | empty | | Loki base URL; must be an absolute `https` URL without user info, query, or fragment |
| `Loki:Authorization` | empty | yes | The complete `Authorization` header value sent to Loki, for example `Basic ...` or `Bearer ...` |
| `OpenTelemetry:OtlpEndpoint` | empty | | Enables OTLP export |

Prometheus metrics are available at `/metrics`. The service/resource name is `SignaCore`.

#### Logging and Loki

Every host phase (Bootstrap Configuration Mode, Setup Mode, and the normal host) logs through the
shared ServiceMantle Serilog pipeline. Structured log fields are sanitized by ServiceMantle before
they reach the Console or Loki, and the sanitization cannot be turned off. Request-scoped entries
carry the `ServiceName`, `ServiceVersion`, and `InstanceId` fields of the ServiceMantle log scope.
The Console uses the ServiceMantle default output template.

Loki export is enabled only on the normal host and only when both `Loki:Uri` (an absolute `https`
URL) and `Loki:Authorization` are set; the credential is stored encrypted with the root key like
every other secret setting and is never returned by the settings API. The management API rejects an
`http` URL, a URL with user info, a query, or a fragment, and a URL or authorization value saved
without the other. Changes take effect after a restart. Bootstrap Configuration Mode and Setup Mode
have no settings yet and only write to the Console.

Loki streams carry only the level label of the shared sink (the former `service=SignaCore` label is
gone); the service identity is in the log properties. Loki being unreachable or rejecting a batch
never affects requests or the Console.

Category levels come from the standard `Logging:LogLevel` section of `appsettings.json` (the former
`Serilog` section is no longer read). The shipped values keep `Microsoft.AspNetCore` and
`Microsoft.EntityFrameworkCore` at `Warning` (`Error` for EF Core in Production); do not lower the
framework categories in production, because framework log lines may then contain request URLs and
query values that structured-field sanitization does not cover.

**Upgrading.** A stored `http` Loki URL or a Loki URL without `Loki:Authorization` does not stop
the service: Loki stays off and the start writes one Console warning naming only the problem
category (`endpoint_not_https`, `endpoint_missing`, `authorization_missing`, or
`authorization_invalid`). Sign in, set an `https` URL and the `Authorization` value, and restart.
Until the Loki pair is corrected, saving any other setting is also refused, because every update
validates the complete candidate.

**Rolling back.** An older release refuses to load a settings aggregate that contains the unknown
`loki.authorization` key. Before starting the older binary, stop every instance and remove the key
from the stored aggregate (new installations and imports store it even when it is empty):

```sql
-- PostgreSQL
UPDATE service_settings
SET values_json = (values_json::jsonb - 'loki.authorization')::text
WHERE service_id = 'signacore';

-- SQLite
UPDATE service_settings
SET values_json = json_remove(values_json, '$."loki.authorization"')
WHERE service_id = 'signacore';
```

The older release then ships to Loki again with its own `Serilog` appsettings section and
`Loki:Uri`; the logging pipeline itself keeps no persistent state.

### Consul service discovery

Consul KV is no longer a configuration authority, and the local plaintext configuration cache has
been removed. Optional service registration remains; its settings are themselves read from the
shared settings aggregate.

| Key | Default | Secret |
| --- | --- | --- |
| `Consul:Host` | `host.docker.internal` | |
| `Consul:Port` | `8500` | |
| `Consul:Token` | empty | yes |
| `Consul:Discovery:Enabled` | `false` | |
| `Consul:Discovery:Register` | `false` | |
| `Consul:Discovery:Deregister` | `false` | must be `true` when registering |
| `Consul:Discovery:ServiceName` | `SignaCore` | |
| `Consul:Discovery:HealthCheckPath` | `/health/ready` | |
| `Consul:Discovery:PreferIPAddress` | `false` | ignored (no auto-detection) |
| `Consul:Discovery:IPAddress` | empty | legacy fallback, ignored when registering |
| `Consul:Discovery:Port` | `0` | legacy fallback, ignored when registering |

Registration is driven by the shared ServiceMantle Consul lifecycle, and each instance must state
its own advertised endpoint through the process configuration (the usual double-underscore
environment-variable form works); the values are required whenever registration is enabled:

| Key | Default | Notes |
| --- | --- | --- |
| `ServiceDiscovery:Address` | none | This instance's advertised address (IP or DNS name) |
| `ServiceDiscovery:Port` | none | This instance's advertised port (1-65535) |
| `ServiceDiscovery:HealthScheme` | `http` | Advertised health URL scheme, `http` or `https` |

See [Consul integration](./ConsulIntegration.md).

## Settings that stay outside the database

| Key | Owner | Notes |
| --- | --- | --- |
| `Endpoints:Http` | appsettings / launcher | Container HTTP port; a deployment concern |
| `APP_TITLE` | launcher | Admin console and document title |
| `Bootstrap:FilePath` | launcher | Optional bootstrap file override |
| `BootstrapApps:FilePath` | appsettings | Optional application pre-seed file |
| `Logging:LogLevel` | appsettings | Log category levels; the Loki address and credential come from the database settings |

Image name, container name, host port, bind mounts, restart policy, timezone, and .NET runtime
switches are deployment concerns owned by the launcher or orchestrator.

### The application pre-seed file

`BootstrapApps:FilePath` points at an optional JSON file that registers applications on first start.
A missing file is normal and only logged; a file that cannot be read or parsed is a warning and does
not stop startup. An `AppId` that already exists is skipped, so the file never overwrites a
registration an administrator has since changed.

Each entry needs `AppId` and `AppSecret`; `AppName` and `CallbackUrl` are optional. `CallbackUrl` is
the server-to-server claims callback.

An entry may also carry an optional `Oidc` section with the interactive OIDC configuration:

```json
{
  "Apps": [
    {
      "AppId": "order-service-bff",
      "AppSecret": "…",
      "AppName": "OrderService BFF",
      "Oidc": {
        "ClientType": "Confidential",
        "AllowAuthorizationCode": true,
        "AllowedScopes": ["openid", "profile"],
        "AllowRefreshToken": false,
        "IdentitySessionMaxAgeSeconds": 1800,
        "AudienceMode": "PerApplication",
        "RedirectUris": ["https://bff.example.test/callback"],
        "PostLogoutRedirectUris": ["https://bff.example.test/signed-out"]
      }
    }
  ]
}
```

Omitting the section — as every file written before it existed does — pre-seeds exactly what it
always did and leaves the application fail closed: `ClientType` `Confidential`,
`AllowAuthorizationCode` `false`, `AllowedScopes` `["openid"]`, `AllowRefreshToken` `false`, no
session max age, and no URI registrations. `CallbackUrl` is never copied into `RedirectUris`.

The section is validated by the same domain rules as
[the administration API](../modules/Admin/AppManagement/02-SPEC.md#interactive-oidc-client-configuration),
so a configuration one path refuses is refused by the other. Validation runs before anything is
written: an entry whose section is unacceptable is logged and skipped, and no partial registration
is left behind. `AudienceMode` appears here because enabling the code flow requires
`PerApplication`, and a pre-seeded application has no administrator to set it first.

Pre-seeding an application activates no OIDC endpoint and changes neither discovery document.

## How secret settings are protected

Sensitive settings are encrypted before being written to the shared `service_settings` aggregate,
as `sm:v1:` envelopes bound to the service id and the normalized setting key. The external root key
from the bootstrap file remains the root of trust:

- the existing derivation for stored RSA private keys is preserved, so upgrading a deployment keeps
  its signing keys decryptable;
- the shared configuration-protection key is derived with its own HKDF domain, separate from the
  signing-key derivation;
- each secret setting is encrypted with AES-GCM and a unique random nonce;
- the service id, setting key, and schema version are bound as authenticated associated data, so an
  envelope cannot be moved from one setting or service into another;
- secret values are never returned from general settings-list APIs.

The database connection string remains protected by bootstrap-file permissions, because it cannot be
stored in the database it is needed to open.

## Changing settings after installation

Settings are validated as one snapshot before activation; a partially valid configuration never
becomes active. A completed installation with missing or invalid required settings fails closed with
the full list of problems and is never rolled back to a pending state — that would reopen anonymous
setup against a database that already owns accounts.

The authenticated console submits changes to `POST /management/v1/settings` as
`{"expectedVersion":N,"changes":[{"key":"...","value":"..."}]}`; a null value removes the explicit
value. Two racing updates over the same expected version have exactly one winner — the loser gets
the fixed 409 and the console keeps the draft for a manual refresh. The update commits one
serializable transaction that carries the aggregate and one key-only audit row per changed key; the
operator is the signed-in management identity.

Every change is currently restart-required. The current-values response carries the product header
`X-SignaCore-Running-Configuration-Version`, which names the version this process activated at
startup — not the version the query just refreshed. When the stored version moves ahead of that
header, the console reports restart pending; a missing or invalid header means "running version
unknown", never "already active". The header describes only the instance that answered the request,
so with multiple instances, coordinate a rolling restart. The active configuration version is also
reported in startup diagnostics.

The authenticated bootstrap editor is separate from database-backed global settings. It never
returns the current connection string, database password, or master key; a replacement connection
is supplied in full and tested before the local file changes. Blank master key means keep the
current key. Raw key replacement is rejected once protected data exists. A bootstrap edit changes
only the instance that served the request, so file distribution and coordinated restart remain
orchestrator responsibilities.
