# security_keys

RSA signing-key metadata and encrypted private parameters.

## Columns

- id (UUID, primary key)
- key_id (JWT kid)
- public_key_exponent / public_key_modulus
- encrypted_private_key_params / encryption_salt
- created_at / expires_at
- is_active

## Relationships and invariants

- No external table owns key material. Only public modulus/exponent values are published through JWKS.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
