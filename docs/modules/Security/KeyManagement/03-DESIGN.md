# Signing Key Management: Design

## Components

KeyManager, IMasterKeyProvider, IPrivateKeyProtector, AesGcmPrivateKeyProtector, and JwksMapper.

## Request flow

1. ASP.NET Core middleware assigns or propagates a correlation identifier.
2. The controller or hosted service validates its security context and input.
3. Domain services apply policy and coordinate repositories.
4. EF Core persists changes using the configured provider.
5. The caller receives a normalized response; failures pass through centralized exception handling.

## Interface

Primary interface: GET /.well-known/jwks, with /.well-known/jwks.json bound to the same handler.
RFC 7517 defines no path for the key set — a conforming client reads `jwks_uri` from discovery — but
the key set is fetched by hand at least as often, and every operator, probe and copied validator
snippet reaches for the `.json` form first. A 404 there is indistinguishable from "this service
publishes no keys", so both paths answer. The routes are declared in `WellKnownEndpoints`, and the
rate limiters treat them identically; the alias must never diverge into a second contract.

## Persistence

Relevant tables: security_keys. PostgreSQL migrations live in Database, while SQLite uses its provider-specific migration assembly.

## Design constraints

- Domain code does not depend on the web host.
- Controllers contain transport concerns, not persistence rules.
- Secrets are never included in diagnostic payloads.
- Async calls propagate CancellationToken.
- Provider-specific behavior must be covered by database contract tests.
