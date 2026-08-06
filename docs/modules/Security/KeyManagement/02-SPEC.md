# Signing Key Management: Requirements

## Overview

SignaCore creates, protects, rotates, and publishes RSA signing keys for JWT issuance and JWKS verification.

## Functional requirements

1. Validate caller authentication and all required inputs before changing state.
2. Execute the operation through the domain and repository abstractions.
3. Return the standard JSON response and an appropriate HTTP status.
4. Preserve transaction boundaries and cancellation-token propagation.
5. Record security-relevant activity where the audit policy requires it.

## Security requirements

Private keys are encrypted at rest with an external master key. Public keys alone are exposed through JWKS, and rotation retains verification overlap.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

## Data

The feature owns or reads security_keys. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.
