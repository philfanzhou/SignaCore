# Audit Logging: Requirements

## Overview

Authentication events and administrative changes are recorded with correlation and request context.

## Functional requirements

1. Validate caller authentication and all required inputs before changing state.
2. Execute the operation through the domain and repository abstractions.
3. Return the standard JSON response and an appropriate HTTP status.
4. Preserve transaction boundaries and cancellation-token propagation.
5. Record security-relevant activity where the audit policy requires it.

## Security requirements

Audit persistence follows the operation-specific commit boundary documented in
[current audit commit evidence](../../../development/ErrorHandling.md#current-audit-commit-evidence):
when audit rows share a transaction with business state, they succeed or roll back together.
Snapshots must exclude credentials, tokens, and key material.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

## Data

The feature owns or reads login_histories and audit_logs. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.
