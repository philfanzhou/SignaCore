# Key Flows

## Token issuance

```text
Client -> /api/auth/token -> application authentication -> grant validator
       -> account and policy checks -> callback claims -> RS256 JWT
       -> rotating refresh token -> audit record -> response
```

## Refresh rotation

A valid, unrevoked, unexpired refresh token must match the requesting application. A successful exchange revokes the old token and creates a replacement. Reuse, expiry, revocation, and application mismatch fail without revealing extra account information.

## Signing-key rotation

The key manager selects an active signing key, creates one when required, encrypts private parameters with the configured master key, and retains overlapping public keys so downstream services can validate tokens issued before rotation.

## SMS authentication

The application policy selects an SMS profile. Admission controls enforce phone normalization, send intervals, hourly/daily limits, expiry, attempts, and lockout. OTP values are stored as MACs, not plaintext.

## Configuration fallback

The service loads Consul KV from `config/signacore`; on failure it attempts the local Consul cache and finally the packaged appsettings values. `/consul/status` reports the active source without exposing tokens.
