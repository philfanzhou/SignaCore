using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SignaCore.Client.AspNetCore;
using SignaCore.Client.AspNetCore.EntityFrameworkCore;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Client.AspNetCore.EntityFrameworkCore.Tests;

/// <summary>
/// One provider-selected database behind the persistent ticket store: a temporary SQLite file or
/// a Testcontainers PostgreSQL instance, plus the service-provider assembly the consumer really
/// uses — a scoped <see cref="DbContext"/> registration, the Data Protection key ring in a
/// directory the test controls, and the registration extension under test. Two key-ring
/// directories model a rotated or lost ring; a deliberately broken context registration models an
/// unreachable database.
/// </summary>
public sealed class TicketStoreDatabase : IAsyncDisposable
{
    private TicketStoreDatabase(
        IAsyncDisposable owner,
        Func<DbContextOptionsBuilder<SessionTicketTestContext>> optionsBuilderFactory,
        string keyRingA,
        string keyRingB)
    {
        Owner = owner;
        OptionsBuilderFactory = optionsBuilderFactory;
        KeyRingA = keyRingA;
        KeyRingB = keyRingB;
    }

    private IAsyncDisposable Owner { get; }

    private Func<DbContextOptionsBuilder<SessionTicketTestContext>> OptionsBuilderFactory { get; }

    /// <summary>The first key-ring directory: the one sessions were written under.</summary>
    public string KeyRingA { get; }

    /// <summary>The second key-ring directory: a rotated-to or rotated-away ring.</summary>
    public string KeyRingB { get; }

    public static async Task<TicketStoreDatabase> CreateAsync(string provider)
    {
        var workspace = Path.Combine(
            Path.GetTempPath(),
            $"signacore-ef-ticket-store-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workspace);
        var keyRingA = Path.Combine(workspace, "ring-a");
        var keyRingB = Path.Combine(workspace, "ring-b");
        Directory.CreateDirectory(keyRingA);
        Directory.CreateDirectory(keyRingB);
        IAsyncDisposable owner = new WorkspaceOwner(workspace);

        if (provider == "SQLite")
        {
            var databasePath = Path.Combine(workspace, "tickets.db");
            // Pooling=false keeps every connection inside this test: no process-wide pool state
            // is shared and nothing here ever clears pools.
            var connectionString = $"Data Source={databasePath};Pooling=false";
            var factory = (Func<DbContextOptionsBuilder<SessionTicketTestContext>>)(() =>
                new DbContextOptionsBuilder<SessionTicketTestContext>()
                    .UseSqlite(connectionString));
            var database = new TicketStoreDatabase(owner, factory, keyRingA, keyRingB);
            await EnsureCreatedAsync(database);
            return database;
        }

        if (provider != "PostgreSQL")
        {
            throw new InvalidOperationException($"Unsupported provider '{provider}'.");
        }

        var image = Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } selected
            ? selected
            : "postgres:15-alpine";
        if (!string.Equals(
                Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS"),
                "true",
                StringComparison.OrdinalIgnoreCase))
        {
            Assert.Skip(
                "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL ticket-store matrix.");
        }

        var container = new PostgreSqlBuilder(image)
            .WithDatabase("ticket_store")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();
        await container.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            var connectionString = container.GetConnectionString();
            var factory = (Func<DbContextOptionsBuilder<SessionTicketTestContext>>)(() =>
                new DbContextOptionsBuilder<SessionTicketTestContext>()
                    .UseNpgsql(connectionString));
            var database = new TicketStoreDatabase(container, factory, keyRingA, keyRingB);
            await WaitUntilConnectableAsync(database);
            await EnsureCreatedAsync(database);
            return database;
        }
        catch
        {
            await container.DisposeAsync();
            throw;
        }
    }

    public SessionTicketTestContext CreateContext() => new(OptionsBuilderFactory().Options);

    public static SessionTicketTestContext CreateSchemaOnlyContext() =>
        new(new DbContextOptionsBuilder<SessionTicketTestContext>()
            .UseSqlite("Data Source=:memory:")
            .Options);

    /// <summary>
    /// Assembles the consumer's real registration shape: a scoped context, the Data Protection
    /// ring in the chosen directory, and the store extension. <paramref name="broken"/> swaps the
    /// context registration for one whose every use throws — an unreachable database without any
    /// SQL or connection detail of its own.
    /// </summary>
    public (EntityFrameworkTicketStore<SessionTicketTestContext> Store, ServiceProvider Services, CapturingLoggerProvider Capture)
        BuildStore(
            TimeProvider? timeProvider = null,
            string? keyRing = null,
            bool broken = false)
    {
        var capture = new CapturingLoggerProvider();
        var keyRingDirectory = new DirectoryInfo(keyRing ?? KeyRingA);
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(capture));
        services.AddDataProtection()
            .PersistKeysToFileSystem(keyRingDirectory)
            .Services
            .AddSingleton<EntityFrameworkTicketStore<SessionTicketTestContext>>()
            .AddSingleton<ITicketStore>(provider =>
                provider.GetRequiredService<EntityFrameworkTicketStore<SessionTicketTestContext>>());
        if (timeProvider is not null)
        {
            services.AddSingleton(timeProvider);
        }

        if (broken)
        {
            services.RemoveAll<DbContextOptions<SessionTicketTestContext>>();
            services.AddScoped<SessionTicketTestContext>(_ =>
                throw new InvalidOperationException("The configured database is unreachable."));
        }
        else
        {
            services.AddScoped(_ => CreateContext());
        }

        // The registration extension must win over the default in-process store regardless of
        // call order: exercise it against a preceding default registration.
        services.AddSingleton<ITicketStore>(static _ => new InMemoryTicketStore());
        services.AddSignaCoreEntityFrameworkTicketStore<SessionTicketTestContext>();

        var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<EntityFrameworkTicketStore<SessionTicketTestContext>>();
        return (store, provider, capture);
    }

    /// <summary>Dumps every row of the table as raw text for the no-plaintext assertions.</summary>
    public async Task<string> DumpAllRowsAsTextAsync()
    {
        await using var context = CreateContext();
        var rows = await context.Set<SignaCoreSessionTicketEntity>()
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken);
        return string.Join(
            "\n",
            rows.Select(row =>
                $"{row.KeyDigest}|{Convert.ToBase64String(row.Payload)}|{row.IssuedUtc:O}|{row.ExpiresUtc:O}"));
    }

    private static async Task EnsureCreatedAsync(TicketStoreDatabase database)
    {
        // Tests create the schema directly; consumers own a migration generated from the same
        // model — the package never ships or executes migrations by contract.
        await using var context = database.CreateContext();
        await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
    }

    private static async Task WaitUntilConnectableAsync(TicketStoreDatabase database)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(60);
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                await using var probe = database.CreateContext();
                if (await probe.Database.CanConnectAsync(TestContext.Current.CancellationToken))
                {
                    return;
                }
            }
            catch (Exception)
            {
                // Retry until the deadline: the container may still be forwarding ports.
            }

            await Task.Delay(200, TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException(
            "The ticket-store contract database did not become connectable within 60s.");
    }

    public async ValueTask DisposeAsync() => await Owner.DisposeAsync();

    private sealed class WorkspaceOwner(string path) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    Directory.Delete(path, recursive: true);
                }
                catch (IOException)
                {
                    // A transient SQLite handle is not this owner's concern.
                }
            });
        }
    }
}

/// <summary>
/// The consumer's own context: the entity set plus the package's mapping extension, nothing
/// else. The consumer generates the migration for its provider from exactly this model.
/// </summary>
public sealed class SessionTicketTestContext(DbContextOptions<SessionTicketTestContext> options)
    : DbContext(options)
{
    public DbSet<SignaCoreSessionTicketEntity> SessionTickets => Set<SignaCoreSessionTicketEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) =>
        modelBuilder.ConfigureSignaCoreTicketStore();
}

/// <summary>Captures every formatted log line the store writes, with its category.</summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly Lock _lock = new();
    private readonly List<(string Category, string Line)> _entries = [];

    public IReadOnlyList<(string Category, string Line)> Entries
    {
        get
        {
            lock (_lock)
            {
                return _entries.ToArray();
            }
        }
    }

    /// <summary>Every line of the ticket store's own categories — the bounded operation log.</summary>
    public IReadOnlyList<string> StoreLines =>
        Entries
            .Where(entry => entry.Category.Contains(
                "EntityFrameworkTicketStore", StringComparison.Ordinal))
            .Select(entry => entry.Line)
            .ToArray();

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(this, categoryName);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(CapturingLoggerProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (owner._lock)
            {
                owner._entries.Add((category, $"{formatter(state, exception)} {exception}"));
            }
        }
    }
}
