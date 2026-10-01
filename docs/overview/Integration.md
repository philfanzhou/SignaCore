# Integration

## Downstream services

Downstream services should use OpenID discovery and JWKS directly:

1. Read `/.well-known/openid-configuration`.
2. Fetch the `jwks_uri` response.
3. validate the RS256 signature, issuer, audience, lifetime, and required claims locally.
4. Refresh cached keys when an unknown `kid` is encountered.

`jwks_uri` resolves to `/.well-known/jwks`. A validator that has to be pointed at a literal URL can
use `/.well-known/jwks.json` instead — it is an alias for the same document — but reading the URL
from discovery is what survives a future route change.

Pure HTTP integration requires no SignaCore assembly. A hosted-login consumer may instead reference the official client package defined by [ADR 0007](../adr/0007-official-hosted-login-client-package.md), the only SignaCore assembly downstream systems may reference. The former client SDK is not maintained.

A service that signs users in should redirect them to SignaCore's hosted login page instead of
collecting credentials itself; the [Hosted Login guide](../integrations/HostedLogin.md) covers
registration, the Authorization Code flow, sign-out, session lifetime, mobile applications, and
migration from the Password and SMS grants.

## External providers

| Integration | Purpose |
| --- | --- |
| SMS providers | Deliver application-scoped OTPs |
| WeChat API | Exchange an authorization code for an external identity |
| LDAP/Active Directory | Validate and bind enterprise identities |
| Callback endpoint | Add application-owned claims after authentication |
| Consul | Optional service registration and discovery; not a configuration source |
| Loki / OTLP / Prometheus | Logs, traces, and metrics; Loki requires an `https` endpoint and an `Authorization` value (see [Configuration](../development/Configuration.md#logging-and-loki)), `/metrics` requires registered application credentials, and OTLP requires HTTPS (see [Configuration](../development/Configuration.md#metrics-and-traces)) |

Callbacks must pass the configured allowed-domain policy and should use HTTPS.
