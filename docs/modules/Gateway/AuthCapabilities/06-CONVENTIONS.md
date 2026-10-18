# Gateway Auth Capabilities: Conventions

- Use the SignaCore root namespace and descriptive domain-oriented type names.
- Keep the route, the two JSON field names, and their boolean types stable.
- Read the application only from the authenticated request; never accept an application selector.
- Answer authentication failures only through the shared generic gateway challenge.
- Send `Cache-Control: no-store` on every answer the route itself produces.
- Pass `CancellationToken` through every asynchronous boundary.
- Never log or return application secrets, phone numbers, provider details, OTPs, or tokens.
- Do not add consumer-specific business rules or branding to the route.
