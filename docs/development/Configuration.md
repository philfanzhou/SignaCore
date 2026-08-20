# Configuration Reference

SignaCore keeps global application configuration in the business database, in the `system_settings`
table. Every instance therefore reads the same active configuration, changes are transactional and
audited, and there is no per-instance configuration drift.

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
  "Database": {
    "Provider": "PostgreSQL",
    "ServerVersion": "15",
    "ConnectionString": "Host=db;Database=signacore;Username=signacore;Password=replace-me"
  },
  "MasterKey": "a-long-random-secret"
}
```

Rules:

- no fields other than `Database.Provider`, `Database.ServerVersion`,
  `Database.ConnectionString`, and inline `MasterKey` are accepted;
- the whole file is a secret and must be readable and writable only by the SignaCore runtime
  identity (`chmod 600` on Unix-like hosts);
- writes use a flushed temporary file in the same directory followed by atomic replacement;
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

These keys are owned by `system_settings`. Defaults are the safe product defaults used to seed a new
installation, and live in versioned application code.

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

| Key | Default | Notes |
| --- | --- | --- |
| `Loki:Uri` | empty | Enables the Loki sink |
| `OpenTelemetry:OtlpEndpoint` | empty | Enables OTLP export |

Prometheus metrics are available at `/metrics`. The service/resource name is `SignaCore`.

### Consul service discovery

Consul KV is no longer a configuration authority, and the local plaintext configuration cache has
been removed. Optional service registration remains; its settings are themselves read from
`system_settings`.

| Key | Default | Secret |
| --- | --- | --- |
| `Consul:Host` | `host.docker.internal` | |
| `Consul:Port` | `8500` | |
| `Consul:Token` | empty | yes |
| `Consul:Discovery:Enabled` | `false` | |
| `Consul:Discovery:Register` | `false` | |
| `Consul:Discovery:Deregister` | `false` | |
| `Consul:Discovery:ServiceName` | `SignaCore` | |
| `Consul:Discovery:HealthCheckPath` | `/health/ready` | |
| `Consul:Discovery:PreferIPAddress` | `false` | |
| `Consul:Discovery:IPAddress` | empty | |
| `Consul:Discovery:Port` | `0` | |

See [Consul integration](./ConsulIntegration.md).

## Settings that stay outside the database

| Key | Owner | Notes |
| --- | --- | --- |
| `Endpoints:Http` | appsettings / launcher | Container HTTP port; a deployment concern |
| `APP_TITLE` | launcher | Admin console and document title |
| `Bootstrap:FilePath` | launcher | Optional bootstrap file override |
| `BootstrapApps:FilePath` | appsettings | Optional application pre-seed file |
| `Logging`, `Serilog` | appsettings | Log pipeline shape; the Loki address comes from `Loki:Uri` |

Image name, container name, host port, bind mounts, restart policy, timezone, and .NET runtime
switches are deployment concerns owned by the launcher or orchestrator.

## How secret settings are protected

Sensitive settings are encrypted before being written to `system_settings`. The external root key
from the bootstrap file remains the root of trust:

- the existing derivation for stored RSA private keys is preserved, so upgrading a deployment keeps
  its signing keys decryptable;
- a separate configuration-protection key is derived with a distinct HKDF info value;
- each secret setting is encrypted with AES-GCM and a unique random nonce;
- the setting key and schema version are bound as authenticated associated data, so an envelope
  cannot be moved from one setting into another;
- secret values are never returned from general settings-list APIs.

The database connection string remains protected by bootstrap-file permissions, because it cannot be
stored in the database it is needed to open.

## Changing settings after installation

Settings are validated as one snapshot before activation; a partially valid configuration never
becomes active. A completed installation with missing or invalid required settings fails closed with
the full list of problems and is never rolled back to a pending state — that would reopen anonymous
setup against a database that already owns accounts.

Every change is currently restart-required. For multiple instances, activate the change and then
coordinate a rolling restart. The active configuration version is reported in startup diagnostics.

The authenticated bootstrap editor is separate from database-backed global settings. It never
returns the current connection string, database password, or master key; a replacement connection
is supplied in full and tested before the local file changes. Blank master key means keep the
current key. Raw key replacement is rejected once protected data exists. A bootstrap edit changes
only the instance that served the request, so file distribution and coordinated restart remain
orchestrator responsibilities.
