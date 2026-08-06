# Error Handling

`ExceptionHandlingMiddleware` is the final boundary for unhandled request exceptions. Controllers should return expected validation and authorization failures explicitly; unexpected failures are logged with the correlation identifier and converted to a stable JSON error response.

## Rules

- Do not return stack traces, connection strings, credentials, tokens, OTPs, or private key material.
- Use appropriate HTTP status codes and a consistent error payload.
- Preserve cancellation rather than converting it into an internal-server error.
- Log structured context, not concatenated secret-bearing request bodies.
- Authentication failures should not reveal whether an account or token exists.
- Audit persistence failures must not cause the primary business operation to fail.

Sensitive request headers are redacted by middleware. Tests cover correlation propagation, exception mapping, and header redaction.
