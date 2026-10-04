# Private-network HTTP testing: policy foundation

The shared `security.hosted_login_http_test_origins` setting establishes a policy foundation for
staged hosted-login HTTP support. **This foundation alone does not enable HTTP hosted login:**
private-network HTTP redirect registration and identity/antiforgery Cookie support remain separate
implementation stages. Existing HTTPS, Secure `__Host-` Cookies and the Development numeric-loopback
redirect exception keep their behavior. Management Bearer authentication does not change.

## Configuration and activation

The setting is a non-sensitive JSON array in the shared `service_settings` aggregate. It is optional,
requires restart, and has no materialized shared default. A missing key or `[]` disables the policy;
existing aggregates need no backfill. First-run and legacy-import complete candidates include `[]`
through the catalog's input defaults. The runtime definition catalog now contains 45 keys.

Edit it through the existing authenticated settings page/API, for example:

```json
["http://192.168.50.10:5002", "http://192.168.50.10:5008", "http://[fd00::10]:5008"]
```

Include the exact identity-host and client callback/logout origins needed by the intended test
deployment. There is no application setting, launcher variable or environment-variable allowlist.
`Security:HostedLoginHttpTestOrigins` is only the internal projection key, not a second authority.

Only a normal Host whose actual `IHostEnvironment.EnvironmentName` is exactly `Testing` may activate
a nonempty list. Bootstrap and Setup have no active snapshot and retain their existing workflow.
After setup, the normal restart checks the policy before application seeding or accepting requests.
The effective Host environment is authoritative; conflicting deployment environment variables cannot
substitute their raw values for that environment. A non-Testing normal Host with a nonempty list
refuses startup with a fixed, value-free English error.

Shared syntax validation allows an administrator to store configuration for a later run. Persisting
a nonempty list on a non-Testing Host therefore succeeds if otherwise valid, but **its next normal
startup is refused**. Changes advance the persisted version; the active policy remains immutable
until restart. The existing running-configuration-version response header and restart-pending UI
continue to describe this difference. Separate Hosts use their own activated snapshots.

## Accepted origins

The JSON document is limited to 8192 characters and at most 32 nonempty strings. Each string must
be an absolute `http://<literal-IP>:<port>` origin with an explicit decimal port from 1 through
65535. IPv4 uses exactly four decimal octets without leading zero aliases; IPv6 uses brackets and
is canonicalized with `IPAddress`. Scheme and IPv6 casing, equivalent IPv6 forms and effective
ports (including explicit port 80) are normalized; duplicate canonical origins are rejected.

Only RFC1918 IPv4 (`10/8`, `172.16/12`, `192.168/16`) and IPv6 ULA (`fc00::/7`) are accepted.
DNS names, `localhost`, loopback, link-local and public addresses, IPv4-mapped IPv6, wildcards,
CIDR, user information, paths (including a trailing slash), query, fragment, percent escapes,
zone identifiers, backslashes and nondecimal ports are rejected. Membership is exact IP plus
port, without network resolution. These origins are configuration data, but validation errors and
startup diagnostics never echo their values.

A nonempty list does not opt into a non-HTTPS issuer. An HTTP public base URL still requires the
existing `security.allow_non_https_issuer=true` and issuer/public-base-URL equality rules. Its exact
authority must additionally be listed. An HTTPS identity Host can activate a Testing list for later
HTTP client registration; its HTTPS Cookie profile remains Secure.

## Deployment and rollback

HTTP provides no transport confidentiality or integrity. Private addresses do not prove trust:
use an isolated test network and enforce access controls. Configure all instances of the test
deployment consistently and restart them. Existing trusted-forwarding rules remain authoritative
for effective request addresses. Later URI stages must still require exact complete-URI registration;
an origin entry alone never authorizes a callback.

No schema, migration, dependency, token or key format changes are introduced. Preserve the database,
bootstrap root key and Data Protection keyring. Before rolling back to a binary whose catalog has
only 44 keys, remove the explicit new entry through the authenticated shared update API by sending
its `value` as `null`, verify the removal, then replace the image. Writing `[]` disables the new
policy but does not remove an unknown key for an older binary. Existing aggregate versions and
audits remain intact. Official dual-end browser/image acceptance belongs to the later complete
HTTP capability, not this policy foundation.
