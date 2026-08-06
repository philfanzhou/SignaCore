# Consul Integration

SignaCore uses Consul for KV configuration and service discovery. The default prefix is `config/signacore`. Configuration can be supplied as JSON values under that prefix; reserved `__comment` fields are ignored.

## Startup sequence

1. Bind Consul connection options from appsettings and environment variables.
2. Load and flatten KV documents under the configured prefix.
3. Save a successful snapshot to the local cache.
4. On Consul failure, load the cache; if that also fails, continue with appsettings.
5. Register the service through Steeltoe when discovery is enabled.

## Diagnostics

- `GET /consul/status` returns the active source, loaded prefixes, key count, cache path, and a sanitized last error.
- `POST /consul/cache/invalidate` clears the local cache when Consul mode is enabled.
- Startup logs mask the ACL token.

## Deployment keys

Use `CONSUL_HTTP_ADDR=host:port` and `CONSUL_TOKEN` for the loader. Discovery options live under `Consul:Discovery`, including `Enabled`, `ServiceName`, `HealthCheckPath`, `Register`, `Deregister`, address, and port.

## Rename migration

Copy or recreate the required KV documents below `config/signacore` and register the new service name `SignaCore`. Keep the former service registration only for the duration of a controlled traffic migration.
