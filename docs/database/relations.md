# Database Relationships

```text
accounts
  +-- password_credentials
  +-- user_logins --< app_sms_accesses >-- app_registrations
  |             --< app_wechat_accesses >-- app_registrations
  +-- ldap_credentials --< app_ldap_accesses >-- app_registrations
  +-- refresh_tokens (also bound to app_id and optional login source; restrictive family_id/parent_id self-references and a restrictive identity_sessions reference)
  +-- login_histories
  +-- identity_sessions (browser identity authority; also restrictively references password_credentials)
  +-- authorization_codes (also restrictively references identity_sessions, app_registrations, and the refresh_tokens family root)

app_registrations
  +-- otps
  +-- app_redirect_uris (interactive redirect and post-logout registrations)
  +-- authorization_requests (login continuations; restrictive reference, no cascade)
  +-- claims callback and login-policy settings
  +-- disabled-by-default interactive OIDC policy
  +-- app_exchange_trusts >-- app_registrations (directed: target accepts source's refresh tokens)

security_keys, login_attempts, and audit_logs are security-owned supporting tables
```

Foreign keys are used where lifecycle ownership is explicit. Some external or historical identifiers, including refresh-token app IDs and audit targets, remain logical references to preserve history and avoid unsafe cascades.

The `app_redirect_uris` foreign key cascades on application deletion. Its unique index covers
application, redirect kind, and the stored canonical URI. Claims callbacks remain columns on
`app_registrations` and do not participate in this relationship.

The `authorization_requests` foreign key to `app_registrations` is restrictive and never cascades in
either direction: deleting an application with live continuation rows fails, and cleanup removes
rows only by retention. Nothing references `authorization_requests`, and the stored redirect URI is
a value snapshot rather than a foreign key to `app_redirect_uris`.

The `identity_sessions` foreign keys to `accounts` and `password_credentials` are both restrictive
and never cascade: deleting a referenced account or credential while session rows exist fails, and
cleanup removes rows only by retention. The `authorization_codes` foreign keys to
`app_registrations`, `accounts`, and `identity_sessions` follow the same `PS-23` rule. Its
`refresh_family_id` column was the single deferred `PS-23` exception: the family migration adds the
restrictive reference to the `refresh_tokens` family root and its lookup index after the legacy
backfill, and it is the one reference that migration both adds and (behind its downgrade gate)
removes. Cleanup removes rows only by retention: the authorization-code segment runs before the
session segment in the same round, and the session cleanup skips sessions still referenced by
retained code rows. Nothing references `authorization_codes`.

The `refresh_tokens` family references are restrictive and never cascade: `family_id` and
`parent_id` reference this table's `id` (a legacy row is the singleton root of its own family, so
its self-reference is deleted with the row itself), `identity_session_id` references
`identity_sessions`, and the unique `parent_id` index gives an interactive parent at most one
child. Deleting a referenced root, parent, or session fails; legacy cleanup deletes only legacy
rows and interactive family cleanup is child-first (see
[Persistence](../oidc/Persistence.md) "Retention and cleanup").
