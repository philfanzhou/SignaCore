# Consul Integration

Consul is optional and is used for service registration only. Registration is owned by the shared
ServiceMantle Consul lifecycle: it reads a derived read-only `discovery.*` view of the activated
product snapshot, registers only while the shared readiness decision is Ready, and deregisters the
same registration id on readiness loss and shutdown.

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

Registration happens when `Consul:Discovery:Enabled` **and** `Consul:Discovery:Register` are both
`true`.

### Legacy switches that changed meaning

- `Consul:Discovery:Deregister` must be `true` whenever registration is enabled: the shared owner
  always deregisters on readiness loss and shutdown, and a deployment that keeps the legacy
  `false` value is **refused at startup** with the fixed configuration code
  `signacore.consul.deregister_required` instead of silently leaking registrations.
- `Consul:Discovery:PreferIPAddress`, `Consul:Discovery:IPAddress`, and `Consul:Discovery:Port` no
  longer take part in registration. There is no address or port auto-detection any more: each
  instance must state its advertised endpoint explicitly (below). A migration from the old
  auto-detected/zero-port behavior must supply the explicit values.

## Instance advertisement

Every registering instance states its own externally reachable endpoint through the process
configuration — the same channel `Bootstrap:FilePath` uses, with the usual double-underscore
environment-variable form (`ServiceDiscovery__Address`):

| Key | Default | Notes |
| --- | --- | --- |
| `ServiceDiscovery:Address` | none | Required when registering: IP literal or DNS name |
| `ServiceDiscovery:Port` | none | Required when registering: 1-65535 |
| `ServiceDiscovery:HealthScheme` | `http` | `http` or `https`; the scheme of the advertised health URL |

A registering deployment without both the address and the port is refused at startup with
`signacore.consul.advertisement_required`. Two instances of the same service advertise their own
distinct address/port pairs and never overwrite or deregister each other.

## Agent endpoint and TLS

The agent endpoint is built from `Consul:Host` and `Consul:Port`:

- A bare `localhost` or loopback IP host becomes `http://host:port/`.
- Any other bare host becomes `https://host:port/` — plain HTTP to a non-loopback agent is not
  accepted. This is a deliberate difference from the retired Steeltoe client, which allowed HTTP
  to any host; the default `host.docker.internal` therefore now produces `https://…:8500/`.
- A host that is itself an absolute URI (`https://consul.example.com`) is used verbatim as the root
  agent URI, ignoring `Consul:Port`.

## Health checks

The registered check is an HTTP probe of the advertised `ServiceDiscovery:Address:Port` +
`Consul:Discovery:HealthCheckPath`, polled by the agent. Point the path at `/health/ready`, not
`/health/live`: readiness gates registration itself, so an instance awaiting first-run setup is
never registered, and an instance that loses readiness is deregistered. This replaces the retired
Steeltoe TTL heartbeat, which only proved the process was alive.

## Changes take effect after a restart

The derived discovery snapshot is activated once at host startup and captured once by the shared
lifecycle. Saving new Consul settings through the management API updates the stored aggregate and
the management views, but the running process keeps its captured configuration — registration
changes of every kind (enable, disable, endpoint, token, advertisement) take effect after a
restart of the process. There is no hot reload.

## Rollback

The Steeltoe wiring and package are removed; there is no in-process switch back to that client.
Rollback requires redeploying a previous image that still contains it. Stop **every** instance of
the service first — two registration owners for the same service must never run concurrently —
then deploy that image with the configuration it accepted (including the auto-detected address
form). This removal changes no database schema or persisted settings. Registrations
left behind by an abnormally terminated instance are cleaned by ordinary Consul operations
tooling; the service does not delete them itself.

## Migrating away from KV configuration

A deployment that previously stored configuration under `config/signacore` does not need to copy it
anywhere: the one-time legacy import reads the effective configuration of the running deployment and
stores it in the database. Supply the former KV values through appsettings or environment variables
for that single start if they are not otherwise present, then delete the KV documents — leaving them
in place has no effect and only invites confusion.

## Real agent acceptance

On Linux with Docker, run:

```sh
RUN_SIGNACORE_CONSUL_TESTS=true dotnet test tests/SignaCore.IntegrationTests/SignaCore.IntegrationTests.csproj -c Release --filter FullyQualifiedName~ConsulRealAgentAcceptanceTests
```

The PR/main `Real Consul Acceptance` job pre-pulls the digest pinned in the fixture and runs
all cases; a missing Docker daemon or agent fails an enabled run. Ordinary runs explicitly skip
the six agent cases and still execute the four canary scanner self-checks.

Two real Program hosts use Kestrel on separate loopback ports and one installed SQLite database.
An isolated Consul agent uses Linux host networking with random HTTP/serf/server ports and no
DNS/gRPC listeners. A transparent loopback proxy forwards the production client's requests to
that agent, recording only safe metadata and token equality. It also exercises initial
unavailability and one lost response after a real registration. The fixture owns and releases
hosts, clients, proxy, agent and temporary database, including failed runs.

Assertions instantiate the [shared lifecycle model](https://github.com/philfanzhou/ServiceMantle/blob/main/docs/contracts/consul-registration-lifecycle.md):
Ready gating, independent identities, actual passing HTTP checks, repeated Ready, readiness loss
and recovery, both stop orders, restart-bound settings, disabled/query-only zero-client behavior,
and caller cancellation with an unknown remote result. Observation deadlines only prevent hung
tests; they are not recovery-time guarantees. The token scan covers captured host log messages,
structured properties and exceptions, available metrics, management projections, and transport
JSON/URLs. Agent logs, process memory, arbitrary external collectors, partitions, SIGKILL cleanup,
DNS/catalog propagation and traffic draining remain outside this acceptance boundary.
