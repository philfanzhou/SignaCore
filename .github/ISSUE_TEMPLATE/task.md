---
name: Task
about: One independently mergeable change.
title: ''
labels: 'type: task'
assignees: ''
---

<!--
Write the body and title in English. Suggested title format: [Module] concise action.
-->

## Background and goal

Describe the symptom, trigger conditions, and impact. Include reproduction steps, failure output, and any affected grants/endpoints/providers or deployment modes.

Related code/docs: `src/...`, `tests/...`, `docs/...`

## Behavior and rules that must be preserved

- State exactly what must not change among HTTP routes, JSON/claims, JWT/JWKS, authentication and authorization, keys, database tables, migrations, configuration, or deployment.
- If the fix must cover multiple paths, state the condition every path has to satisfy and where the unified fix should land.

## Scope

- What will change.
- **Explicit exclusions**: especially limits such as "do not change existing token compatibility", "do not rename tables", "do not refactor X", "do not expose secrets".

## Explicitly not included and not guaranteed

- Guaranteed:
- Not guaranteed:
- Caller responsibilities:

## Acceptance criteria

- Success results that can be verified item by item.
- Applicable failure, cancellation, security, authentication, key, migration, and concurrency results; write "not applicable" with a reason when they do not apply.
- When APIs, tokens, the database, or configuration are involved, state the compatibility and rollback outcomes.

## Documentation and compatibility impact

State whether API, JSON/claims, JWT, database/migrations, configuration, the admin console, containers, deployment, or English user-facing documentation are affected; write "None" when there is no impact.

## Dependencies

- GitHub native Blocked by: #NNN, or "None"
- GitHub native Blocks: #NNN, or "None"

## Delivery constraints

- When public behavior or usage changes, update the English README, docs, API documentation, and migration notes in step.
