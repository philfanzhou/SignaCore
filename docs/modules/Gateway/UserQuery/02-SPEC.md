# Gateway User Query: Requirements

## Overview

Trusted gateway applications query normalized account and sign-in information for downstream services.

## Functional requirements

1. Validate caller authentication and all required inputs before changing state.
2. Execute the operation through the domain and repository abstractions.
3. Return the standard JSON response and an appropriate HTTP status.
4. Preserve transaction boundaries and cancellation-token propagation.
5. Record security-relevant activity where the audit policy requires it.

## Security requirements

Gateway endpoints use registered-application authentication and never expose password hashes, refresh tokens, or key material.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

## Data

The feature owns or reads accounts, user_logins, and password_credentials. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.
