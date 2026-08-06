# Token Issuance: Requirements

## Overview

Clients exchange password, SMS, WeChat, LDAP, or refresh-token credentials for an RS256 JWT and a rotating refresh token.

## Functional requirements

1. Validate caller authentication and all required inputs before changing state.
2. Execute the operation through the domain and repository abstractions.
3. Return the standard JSON response and an appropriate HTTP status.
4. Preserve transaction boundaries and cancellation-token propagation.
5. Record security-relevant activity where the audit policy requires it.

## Security requirements

Every request is bound to a registered application. Secrets are verified with library primitives, refresh tokens rotate, and failures do not expose account existence.

All logs and errors must redact passwords, application secrets, refresh tokens, OTP values, authorization headers, and private key material.

## Data

The feature owns or reads accounts, app_registrations, password_credentials, otps, user_logins, login_attempts, and refresh_tokens. Database access remains behind repository interfaces and the unit-of-work/IdentityDbContext boundaries.

## Compatibility

Public HTTP routes, JSON property names, and database table names remain stable across the SignaCore rename. Only product, namespace, assembly, image, and deployment identifiers changed.
