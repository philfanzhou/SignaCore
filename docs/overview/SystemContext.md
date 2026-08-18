# System Context

SignaCore is the central identity provider for a service ecosystem. Users authenticate through SignaCore; trusted applications and gateways receive signed JWTs; downstream services validate those tokens locally from the published JWKS.

```text
Users and administrators
          |
          v
      SignaCore <------> PostgreSQL / SQLite
       |   |
       |   +---------> SMS, WeChat, LDAP, callback services
       |
       +-------------> Consul, Loki, OTLP collector
       |
       +-- RS256 JWT --> gateways and business services
                          |
                          +-- JWKS-based local validation
```

## Trust boundaries

- Public authentication endpoints validate registered application credentials.
- Administrative endpoints require the bootstrap or delegated admin role.
- Gateway endpoints require gateway application authentication.
- Downstream services do not reference SignaCore assemblies; they validate JWTs using standard HTTP discovery and JWKS.
- Private signing keys and application secrets never cross the service boundary.
