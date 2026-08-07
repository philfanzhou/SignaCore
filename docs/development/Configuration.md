# Configuration Reference

Configuration precedence is command line, environment variables, Consul KV, Consul cache, environment-specific appsettings, then `appsettings.json`. Environment variables use ASP.NET Core double-underscore nesting.

## Core settings

| Key | Default | Notes |
| --- | --- | --- |
| `APP_TITLE` | `SignaCore` | Admin console and document title |
| `Endpoints:Http` | `5002` | Container HTTP port |
| `Database:Provider` | `PostgreSQL` | PostgreSQL, MySQL, MariaDB, or SQLite |
| `Database:ServerVersion` | `15` | Required for MySQL/MariaDB compatibility selection |
| `Database:ConnectionString` | development only | Required production connection |
| `Endpoints:PublicBaseUrl` | request origin | External origin used to build discovery URLs behind a proxy |
| `Jwt:Issuer` | `SignaCore` | Must match downstream validation; see [conformance](../overview/StandardsConformance.md) |
| `Jwt:Audience` | `SignaCore.Services` | Must match downstream validation |
| `Jwt:TokenExpirationHours` | `2` | Access-token lifetime |
| `RefreshToken:ExpirationDays` | `7` | Refresh-token lifetime |

## WeChat

| Key | Default | Notes |
| --- | --- | --- |
| `WeChat:AppId` | empty | Required before any application may leave `wechat_login_mode = Disabled` |
| `WeChat:AppSecret` | empty | Must be set together with `WeChat:AppId` |
| `WeChat:ApiBaseUrl` | `https://api.weixin.qq.com` | Must be https, except for a loopback stub |

Startup fails when only one of `WeChat:AppId` / `WeChat:AppSecret` is present. When both are absent,
WeChat login stays unavailable and the admin API refuses to enable a WeChat mode, instead of issuing
requests to WeChat with an empty appid.

## Secret settings

The deployment environment must supply `RSA_MASTER_KEY`, `ADMIN_BOOTSTRAP_PASSWORD`, application secrets, provider credentials, and `Sms:OtpHmacKey`. `Sms:BypassCode` is disabled when empty and is only accepted for allow-listed `Sms:BypassPhones`. Never store production secrets in appsettings, scripts, logs, or Consul snapshots committed to source control.

## Consul

| Key | Default |
| --- | --- |
| `Consul:Host` | `host.docker.internal` |
| `Consul:Port` | `8500` |
| `Consul:ServiceName` | `SignaCore` |
| `Consul:KvPrefix` | `config/signacore` |
| `Consul:EnableCache` | `true` |
| `Consul:CacheDirectory` | `./data/consul` |

`CONSUL_HTTP_ADDR`, `CONSUL_HOST`, `CONSUL_PORT`, and `CONSUL_TOKEN` are supported deployment variables. See [Consul integration](./ConsulIntegration.md).

## Observability

`Loki:Uri` configures the Loki sink. `OpenTelemetry:OtlpEndpoint` enables OTLP export. Prometheus metrics are available at `/metrics`. The service/resource name is `SignaCore`.

## Rename compatibility

To accept tokens issued before the rename, temporarily override `Jwt:Issuer` and `Jwt:Audience` with their former deployed values, or coordinate a token-expiry cutover. Copy KV values from the former prefix to `config/signacore` before switching. Point `Database:ConnectionString` at the existing database to retain data; the default database name is only a deployment default.
