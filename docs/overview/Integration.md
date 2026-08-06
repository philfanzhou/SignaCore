# Integration

## Downstream services

Downstream services should use OpenID discovery and JWKS directly:

1. Read `/.well-known/openid-configuration`.
2. Fetch the `jwks_uri` response.
3. validate the RS256 signature, issuer, audience, lifetime, and required claims locally.
4. Refresh cached keys when an unknown `kid` is encountered.

No SignaCore assembly or private client SDK is required. The former client SDK is not maintained.

## External providers

| Integration | Purpose |
| --- | --- |
| SMS providers | Deliver application-scoped OTPs |
| WeChat API | Exchange an authorization code for an external identity |
| LDAP/Active Directory | Validate and bind enterprise identities |
| Callback endpoint | Add application-owned claims after authentication |
| Consul | KV configuration and service discovery |
| Loki / OTLP / Prometheus | Logs, traces, and metrics |

Callbacks must pass the configured allowed-domain policy and should use HTTPS.
