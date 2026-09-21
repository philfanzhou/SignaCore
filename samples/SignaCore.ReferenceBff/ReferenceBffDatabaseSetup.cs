using Microsoft.EntityFrameworkCore;
using SignaCore.ReferenceBff.Database;

namespace SignaCore.ReferenceBff;

/// <summary>
/// The reference BFF's own database startup configuration. Opening the BFF database is one of the
/// two provider-level exceptions to "no business settings in appsettings": the provider and
/// connection string are exactly what a host needs before it can open its storage.
/// </summary>
internal static class ReferenceBffDatabaseSetup
{
    internal const string ProviderKey = "ReferenceBffDatabase:Provider";
    internal const string ConnectionStringKey = "ReferenceBffDatabase:ConnectionString";

    /// <summary>
    /// The parsed database configuration: fully absent means the sample runs its login-only shape;
    /// anything partially present is a startup failure with a fixed message that echoes no value.
    /// </summary>
    internal sealed record Settings(bool IsConfigured, string Provider, string ConnectionString)
    {
        public static readonly Settings None = new(false, string.Empty, string.Empty);
    }

    internal static Settings Read(IConfiguration configuration)
    {
        var provider = configuration[ProviderKey];
        var connectionString = configuration[ConnectionStringKey];
        var hasProvider = !string.IsNullOrWhiteSpace(provider);
        var hasConnectionString = !string.IsNullOrWhiteSpace(connectionString);

        if (!hasProvider && !hasConnectionString)
        {
            return Settings.None;
        }

        if (!hasProvider
            || !hasConnectionString
            || !string.Equals(provider, "SQLite", StringComparison.Ordinal)
                && !string.Equals(provider, "PostgreSQL", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The reference BFF database configuration is invalid: ReferenceBffDatabase:Provider and "
                + "ReferenceBffDatabase:ConnectionString must be provided together, and Provider must be "
                + "SQLite or PostgreSQL.");
        }

        return new Settings(true, provider!, connectionString!);
    }

    /// <summary>
    /// Wires the chosen provider with the BFF's own migration histories — the same wiring as the
    /// database project's <c>UseReferenceBffSqlite</c>/<c>UseReferenceBffPostgreSql</c> extensions,
    /// on the non-generic builder the hosting overload hands over. No retrying execution strategy,
    /// and deliberately no Migrate/EnsureCreated/seed: the operator migrates before starting, and
    /// a missing schema answers as a bounded failure at request time.
    /// </summary>
    internal static void ConfigureDbContext(
        DbContextOptionsBuilder options,
        Settings settings)
    {
        if (string.Equals(settings.Provider, "SQLite", StringComparison.Ordinal))
        {
            options.UseSqlite(
                settings.ConnectionString,
                providerOptions => providerOptions.MigrationsAssembly(
                    ReferenceBffDatabaseOptionsExtensions.SqliteMigrationsAssemblyName));
            return;
        }

        options.UseNpgsql(
            settings.ConnectionString,
            providerOptions => providerOptions.MigrationsAssembly(
                typeof(ReferenceBffDbContext).Assembly.FullName));
    }
}
