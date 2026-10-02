# SignaCore.Client.AspNetCore.EntityFrameworkCore

The persistent server-side session store for the
[SignaCore.Client.AspNetCore](https://www.nuget.org/packages/SignaCore.Client.AspNetCore) hosted-login
client. Sessions live in your own database: they survive restarts, they are shared across
replicas, and revocation is one atomic database statement. The database holds only the SHA-256
digest of the opaque session key and a Data Protection-encrypted payload — never a plaintext key,
token, or principal.

## Getting started

Add the store to your `DbContext` and generate the migration yourself — this package never
creates or executes migrations, exactly like the rest of your schema:

```csharp
using SignaCore.Client.AspNetCore.EntityFrameworkCore;

public class OrderServiceDbContext : DbContext
{
    public DbSet<SignaCoreSessionTicketEntity> SessionTickets => Set<SignaCoreSessionTicketEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) =>
        modelBuilder.ConfigureSignaCoreTicketStore();
}
```

```bash
dotnet ef migrations add AddSignaCoreSessionTickets
dotnet ef database update
```

Register it with the hosted-login client — the call order against
`AddSignaCoreHostedLogin` does not matter, the persistent store always wins over the default
in-process one:

```csharp
builder.Services.AddSignaCoreEntityFrameworkTicketStore<OrderServiceDbContext>();
builder.Services.AddSignaCoreHostedLogin(options => { /* ... */ });
```

Both of SignaCore's own providers are covered by the store's contract tests (PostgreSQL through
Npgsql and SQLite), and any other EF Core relational provider that speaks standard SQL will work:
the mapping is one digest-keyed table (`signacore_client_session_tickets`) with a plain expiry
index, and the package references only provider-neutral EF Core relational — your application
brings the provider.

## Storage and security model

- The browser's opaque session key is never stored. The table is keyed by the base64 SHA-256
  digest of that key, so a database leak alone cannot be replayed as a session cookie.
- The ticket payload — the principal, the access token, and the ID token — is serialized with the
  framework's authentication-ticket serializer and encrypted with ASP.NET Core Data Protection
  before it reaches the database.
- Revocation (`RemoveAsync`) is one atomic `DELETE` on the digest: concurrent revocations all
  complete while exactly one deletes the row. The package's own
  `TakeAsync(key, cancellationToken)` is the atomic take-and-revoke form: of any number of
  concurrent callers exactly one receives the ticket snapshot — the building block a
  local-session-first prepared logout uses to guarantee at most one upstream preparation.
- Expired rows are reclaimed at read time and by the client package's existing periodic sweep;
  no extra background service is needed.
- An expired, unknown, corrupt, or unreadable key answers `null`: authentication fails closed.
  Store failures log one fixed category (`ticket_store_unavailable`) and never include SQL text,
  connection details, keys, or tokens.

## Operating the Data Protection key ring

The encrypted payloads are only as durable as your Data Protection key ring:

- **Persist the ring.** The default in-process ring loses every session on restart — configure a
  file directory, a database, or your platform's key store (for example
  `PersistKeysToFileSystem`, or the Azure/blob extensions).
- **Share the ring across replicas.** Every instance reading the store must be able to unprotect
  payloads written by any other instance; a replica with a different ring sees every stored
  session as unreadable and answers `unauthenticated`.
- **Rotate on purpose.** A key that is retired or deleted turns the sessions encrypted under it
  into unreadable records: they fail closed and are removed on access. Users sign in again —
  plan rotations with that expectation.
- The Data Protection purpose is fixed (`SignaCore.Client.AspNetCore.EntityFrameworkCore.SessionTicket.v1`);
  payloads encrypted by one version of the store stay readable by later versions.

## Responsibilities

This package owns persistence and the encrypted shape of the stored session. You own the
database, the migration, capacity and retention beyond the built-in expiry sweep, and the Data
Protection key ring. Refresh-token handling and business authorization stay with the client
package's extension points, unchanged.
