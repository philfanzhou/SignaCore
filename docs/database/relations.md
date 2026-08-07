# Database Relationships

```text
accounts
  +-- password_credentials
  +-- user_logins --< app_sms_access >-- app_registrations
  |             --< app_wechat_accesses >-- app_registrations
  +-- ldap_credentials --< app_ldap_access >-- app_registrations
  +-- refresh_tokens (also bound to app_id and optional login source)
  +-- login_histories

app_registrations
  +-- otps
  +-- callback and login-policy settings

security_keys, login_attempts, and audit_logs are security-owned supporting tables
```

Foreign keys are used where lifecycle ownership is explicit. Some external or historical identifiers, including refresh-token app IDs and audit targets, remain logical references to preserve history and avoid unsafe cascades.
