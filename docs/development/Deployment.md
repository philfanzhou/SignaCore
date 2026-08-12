# Deployment

## Build

```bash
IMAGE_TAG=latest ./build.sh
```

This produces `signacore:latest` from `src/SignaCore.Host/Dockerfile`. The image builds the Vue admin application, restores and publishes `SignaCore.Host`, runs as the non-root `app` user, exposes port 5002, and starts `SignaCore.Host.dll`.

## Run

`start.sh` defaults to image `signacore:latest` and container `signacore`. Set required secrets in the shell or secret manager before invoking it:

```bash
export ADMIN_BOOTSTRAP_PASSWORD='replace-me'
export RSA_MASTER_KEY='long-random-secret-from-secret-manager'
export JWT_ISSUER='https://identity.example.com'
export PUBLIC_BASE_URL='https://identity.example.com'
export DATABASE_CONNECTION_STRING='Host=db;Database=signacore;Username=signacore;Password=replace-me'
export SMS_BYPASS_CODE=''
export SMS_BYPASS_PHONES=''
export SMS_OTP_HMAC_KEY='base64-encoded-key'
export CONSUL_TOKEN='token-if-required'
./start.sh
```

The script mounts `./data` at `/app/data`, where bootstrap applications, signing-key material, and the
Consul cache may be stored. It resolves the requested tag to its image ID before changing containers,
waits for `/health`, and restores the previous container automatically when startup, health
verification, or the deployment script itself fails or is interrupted. `curl` is required on the deployment host. Back up the data directory according to
the deployment's key-management policy.

The launcher gives the old container 35 seconds to shut down cleanly. A rollback restores the prior
container image and configuration, but it does not reverse database migrations; keep migrations
backward-compatible and take a verified database backup before deployment.

The launcher also maps these optional operator variables to ASP.NET Core settings:

| Operator variable | Application setting |
| --- | --- |
| `DATABASE_PROVIDER`, `DATABASE_SERVER_VERSION`, `DATABASE_CONNECTION_STRING` | `Database:*` |
| `JWT_ISSUER`, `JWT_AUDIENCE` | `Jwt:*` |
| `ALLOW_NON_HTTPS_ISSUER` | temporary `Security:AllowNonHttpsIssuer` compatibility switch |
| `PUBLIC_BASE_URL` | required production `Endpoints:PublicBaseUrl` canonical HTTPS URL (unless supplied by Consul) |
| `ADMIN_WEB_ORIGIN` | first `AdminWeb:AllowedOrigins` entry |
| `CALLBACK_ALLOWED_DOMAIN` | first `Callback:AllowedDomains` entry |
| `CALLBACK_ALLOW_PRIVATE_ADDRESSES`, `CALLBACK_REQUIRE_HTTPS` | callback security policy |
| `REVERSE_PROXY_IP` | first trusted reverse proxy address |
| `OTLP_ENDPOINT`, `LOKI_URI` | observability exporters |

## Production checklist

- Terminate TLS at the service or a trusted reverse proxy.
- Set `REVERSE_PROXY_IP` when TLS terminates at a non-loopback proxy so forwarded scheme and client IP
  are accepted only from that proxy.
- Use a production database and verify the selected provider's migrations.
- Supply all secrets externally and restrict file permissions.
- Set the JWT issuer/audience expected by downstream services.
- Publish `/.well-known/openid-configuration` and JWKS through the public base URL.
- Configure Consul health checks for `/health`.
- Scrape `/metrics` and connect logs/traces to the chosen observability backend.
- Run the verification steps after deployment.

## Upgrade from the former name

1. Build and distribute the `signacore` image.
2. Copy Consul KV to `config/signacore` and update discovery consumers to `SignaCore`.
3. Reuse the existing database by retaining its connection string, or migrate data explicitly before using the new default database name.
4. Coordinate the JWT issuer/audience cutover; old tokens remain valid only when validators accept their original values.
5. Replace old container names, dashboards, log labels, alerts, and deployment commands.
6. Remove the old instance after health, authentication, JWKS, and database migration checks pass.
