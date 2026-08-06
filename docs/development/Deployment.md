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
export SMS_BYPASS_CODE=''
export SMS_BYPASS_PHONES=''
export SMS_OTP_HMAC_KEY='base64-encoded-key'
export CONSUL_TOKEN='token-if-required'
./start.sh
```

The script mounts `./data` at `/app/data`, where bootstrap applications, signing-key material, and the Consul cache may be stored. Back up that directory according to the deployment's key-management policy.

## Production checklist

- Terminate TLS at the service or a trusted reverse proxy.
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
