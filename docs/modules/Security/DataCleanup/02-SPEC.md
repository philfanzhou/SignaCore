# Security Data Cleanup: Requirements

## Overview

A background worker removes expired security records according to configured retention windows.

## Functional requirements

1. Validate caller authentication and all required inputs before changing state.
2. Execute the operation through the domain and repository abstractions.
3. Return the standard JSON response and an appropriate HTTP status.
4. Preserve transaction boundaries and cancellation-token propagation.
5. Record security-relevant activity where the audit policy requires it.

## Security requirements

Cleanup is bounded, cancellable, and limited to records that satisfy explicit expiry or retention predicates.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

## Data

The feature owns or reads refresh_tokens, otps, and login_attempts. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.
