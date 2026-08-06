# User Management: Conventions

- Use the SignaCore root namespace and descriptive domain-oriented type names.
- Keep routes and JSON field names compatible with the existing API.
- Use UTC timestamps and Guid identifiers.
- Pass CancellationToken through every asynchronous boundary.
- Use structured logging with correlation identifiers; never log credentials or tokens.
- Return errors through the centralized API error format.
- Keep database access provider-neutral unless code is located in a provider-specific migration project.
