# WeChat Binding: Conventions

- Use the SignaCore root namespace and descriptive domain-oriented type names.
- Keep routes and JSON field names compatible with the existing API.
- Return masked OpenId values (`SensitiveDataMasker.MaskOpenId`) from every API response and log statement.
- Use UTC timestamps and Guid identifiers.
- Pass CancellationToken through every asynchronous boundary.
- Use structured logging with correlation identifiers; never log credentials or tokens.
- Return errors through the centralized API error format; conflicts use HTTP 409.
- Keep database access provider-neutral unless code is located in a provider-specific migration project.
