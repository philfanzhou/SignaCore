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

## Startup and configuration

```text
bootstrap file absent -> minimal live/not-ready host -> protected /bootstrap workflow
    -> validate database + key -> atomic mode-0600 file write -> controlled restart

writable protected bootstrap file -> derive root key -> connect business database
    -> migration lock -> apply migrations -> read installation_state
    -> Pending: Setup Mode          (only /setup, /api/setup/*, /health/*)
    -> Completed: load and validate the system_settings snapshot -> normal host
```

There is no production configuration fallback once a file exists. Database unavailability is a
`Completed` installation whose required settings are missing or invalid fails closed rather than
reverting to a pending state — reverting would reopen anonymous setup against a database that already
owns accounts.

## First-run setup

```text
empty database -> create Pending installation + one-time setup code (printed once to stdout)
   -> operator opens /setup -> submits public base URL, administrator credentials, setup code
   -> one serializable transaction: seed default settings, create administrator, audit,
      mark Completed, invalidate the code
   -> process stops; supervisor restarts it into the normal host
```

Only one concurrent request can complete an installation. A database that already contains business
data but has no installation state takes the protected legacy import path instead, and never exposes
setup.
