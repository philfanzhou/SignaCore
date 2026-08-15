# Consul Integration

Consul is optional and is used for service registration and discovery only.

Consul KV is **not** a configuration authority. Global application configuration lives in the business
database (`system_settings`); the database connection and the external root key live in the read-only
bootstrap file. The former KV loader, its precedence rules, and the local plaintext configuration
cache have been removed, along with the `/consul/status` and `/consul/cache/invalidate` endpoints.

## Enabling discovery

Discovery is disabled by default. Its settings are themselves read from `system_settings` after the
database bootstrap phase, so they are configured like any other setting rather than through
environment variables:

| Key | Default |
| --- | --- |
| `Consul:Host` | `host.docker.internal` |
| `Consul:Port` | `8500` |
| `Consul:Token` | empty (stored encrypted) |
| `Consul:Discovery:Enabled` | `false` |
| `Consul:Discovery:Register` | `false` |
| `Consul:Discovery:Deregister` | `false` |
| `Consul:Discovery:ServiceName` | `SignaCore` |
| `Consul:Discovery:HealthCheckPath` | `/health/ready` |
| `Consul:Discovery:PreferIPAddress` | `false` |
| `Consul:Discovery:IPAddress` | empty |
| `Consul:Discovery:Port` | `0` |

Registration happens through Steeltoe when `Consul:Discovery:Enabled` is true.

## Health checks

Point the Consul check at `/health/ready`, not `/health/live`. An instance awaiting first-run setup is
live but deliberately not ready, and must not receive authentication traffic.

## Migrating away from KV configuration

A deployment that previously stored configuration under `config/signacore` does not need to copy it
anywhere: the one-time legacy import reads the effective configuration of the running deployment and
stores it in the database. Supply the former KV values through appsettings or environment variables
for that single start if they are not otherwise present, then delete the KV documents — leaving them
in place has no effect and only invites confusion.
