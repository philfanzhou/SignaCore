# Database Relationships

```text
accounts
  +-- password_credentials
  +-- user_logins --< app_sms_accesses >-- app_registrations
  |             --< app_wechat_accesses >-- app_registrations
  +-- ldap_credentials --< app_ldap_accesses >-- app_registrations
  +-- refresh_tokens (also bound to app_id and optional login source)
  +-- login_histories

app_registrations
  +-- otps
  +-- app_redirect_uris (interactive redirect and post-logout registrations)
  +-- claims callback and login-policy settings
  +-- disabled-by-default interactive OIDC policy
  +-- app_exchange_trusts >-- app_registrations (directed: target accepts source's refresh tokens)

security_keys, login_attempts, and audit_logs are security-owned supporting tables
```

Foreign keys are used where lifecycle ownership is explicit. Some external or historical identifiers, including refresh-token app IDs and audit targets, remain logical references to preserve history and avoid unsafe cascades.

The `app_redirect_uris` foreign key cascades on application deletion. Its unique index covers
application, redirect kind, and the stored canonical URI. Claims callbacks remain columns on
`app_registrations` and do not participate in this relationship.
