> Always write the body in English. Use the English conventional commit format for the title (`feat:` / `fix:` / `docs:` ...).

## Overview

Explain the problem being solved and what this change does.

Closes #

## Scope

Quote the "Scope" section of the linked issue and account for every item:

- **In scope, completed:**

## Behavior guarantees and compatibility

- **What is and is not guaranteed:** whether it matches the issue; write "None" if not applicable.
- **HTTP API, JSON, claims, JWT/JWKS, and authentication:**
- **PostgreSQL/SQLite schema, migrations, and data:**
- **Configuration, admin console, containers, and deployment:**
- **English user-facing documentation:**

Write "None" for items with no impact.

## Verification

List the commands actually run, their results, and any skips with reasons:

- [ ] .NET Release build passes
- [ ] Unit tests pass
- [ ] Applicable HTTP/auth/database integration tests pass
- [ ] Applicable PostgreSQL and SQLite migration/contract checks pass
- [ ] Admin console tests and production build pass
- [ ] When containers or deployment are involved, image and smoke tests pass
- [ ] When behavior, configuration, or usage changes, English documentation is updated in step
- [ ] No secrets, connection strings, credentials, tokens, or private data included
