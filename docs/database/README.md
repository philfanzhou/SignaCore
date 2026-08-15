# Database

SignaCore uses one EF Core model with provider-specific migrations for PostgreSQL, MySQL/MariaDB, and SQLite.

## Tables

| Table | Purpose |
| --- | --- |
| [accounts](./tables/accounts.md) | Canonical user account state. |
| [app_registrations](./tables/app_registrations.md) | Registered client applications and their authentication policies. |
| [audit_logs](./tables/audit_logs.md) | Administrative and security-relevant change records. |
| [installation_state](./tables/installation_state.md) | Singleton first-run/installation marker and one-time setup-code state. |
| [login_attempts](./tables/login_attempts.md) | Password-login failure counts and lockout state by normalized username. |
| [login_histories](./tables/login_histories.md) | Successful and failed authentication event history. |
| [otps](./tables/otps.md) | Application-scoped SMS one-time-password state and rate limiting. |
| [password_credentials](./tables/password_credentials.md) | Local username/password bindings. |
| [refresh_tokens](./tables/refresh_tokens.md) | Rotating, revocable refresh credentials bound to an account and application. |
| [security_keys](./tables/security_keys.md) | RSA signing-key metadata and encrypted private parameters. |
| [system_settings](./tables/system_settings.md) | Global application configuration, with secret values encrypted. |
| [user_logins](./tables/user_logins.md) | External provider identity bindings, including phone and WeChat identities. |
| `ldap_credentials` | LDAP directory identity bindings |
| `app_ldap_access` | Per-application LDAP access approvals |
| `app_sms_access` | Per-application SMS user approvals |
| [app_wechat_accesses](./tables/app_wechat_accesses.md) | Per-application WeChat identity admissions |

See [relationships](./relations.md) and [migration operations](./migrations.md).

## Naming compatibility

The product rename does not rename existing tables, columns, indexes, or migration identifiers. Only CLR namespaces and migration assembly names changed.
