using Microsoft.EntityFrameworkCore;
using ServiceMantle;
using ServiceMantle.AspNetCore;
using ServiceMantle.Configuration;
using ServiceMantle.Database.PostgreSql;
using ServiceMantle.Database.Sqlite;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;

namespace SignaCore.Host;

/// <summary>
/// The minimal ServiceMantle composition shared by the Bootstrap, Setup, and normal hosts.
/// </summary>
/// <remarks>
/// The host identity and the shared bootstrap file store are registered: the file lifecycle
/// (locate, read, create, replace) belongs to the shared store, with the PostgreSQL and SQLite
/// bootstrap providers registered so the store resolves both. The Correlation ID middleware
/// remains the only ServiceMantle HTTP capability activated in the Bootstrap and Setup hosts; the
/// normal host composes more. The installation state, the business database, authentication, and
/// Serilog remain owned by SignaCore. The ServiceMantle request log scope adds its own
/// ServiceName, ServiceVersion, and InstanceId fields; the existing global Serilog enrichment is
/// intentionally left unchanged.
/// </remarks>
internal static class ServiceMantleComposition
{
    internal const string ServiceIdentifier = "signacore";

    /// <summary>
    /// Registers the ServiceMantle host identity and the shared bootstrap file store. The instance
    /// id is generated once per host build (<c>signacore-</c> plus a GUID in N format) and is used
    /// for request log scope fields only; it is not a persistent identity. The service version is
    /// left unset so ServiceMantle resolves the entry assembly version. All three hosts must pass
    /// the same <paramref name="bootstrapFilePath"/> — resolved from the
    /// <c>Bootstrap:FilePath</c> override — so the DI store and the pre-composition store agree.
    /// </summary>
    internal static void AddSignaCoreServiceMantle(
        this IServiceCollection services,
        string? bootstrapFilePath = null)
    {
        var builder = services.AddServiceMantle(
            ServiceId.Parse(ServiceIdentifier),
            InstanceId.Parse($"{ServiceIdentifier}-{Guid.NewGuid():N}"),
            bootstrapFilePath);
        builder.AddBootstrapDatabaseProvider<PostgreSqlBootstrapDatabaseProvider>();
        builder.AddBootstrapDatabaseProvider<SqliteBootstrapDatabaseProvider>();
    }

    /// <summary>
    /// Registers the shared ServiceMantle setting stack in the normal host: the product definitions,
    /// the composite validator, the EF Core single-aggregate store, the transactional update path,
    /// the root key source, and the snapshot/query services.
    /// </summary>
    /// <remarks>
    /// This is a parallel addition: the legacy <c>system_settings</c> path, its endpoints, and the
    /// first-run setup write path stay untouched; the new aggregate starts empty at version 0.
    /// Setup and Bootstrap mode hosts deliberately do not register any of this. The update
    /// transaction and update service are scoped over the same scoped <c>IdentityDbContext</c> the
    /// host already registers; the store owns its contexts through the factory.
    /// </remarks>
    internal static IServiceCollection AddSignaCoreSharedSettings(
        this IServiceCollection services,
        DatabaseOptions databaseOptions,
        bool isDevelopment)
    {
        services.AddSingleton<IServiceSettingDefinitionProvider, ServiceSettingDefinitions>();
        services.AddSingleton<IServiceSettingCompositeValidator>(_ =>
            new SignaCoreSettingCompositeValidator(isDevelopment));
        services.AddSingleton<IServiceSettingRootKeySource, MasterKeyRootKeySource>();

        // The shared store creates and releases its own contexts; both registrations use the same
        // provider options as the scoped business context.
        services.AddDbContextFactory<IdentityDbContext>(
            options => options.UseIdentityDatabase(databaseOptions));
        services.AddSingleton<IServiceSettingStore>(serviceProvider =>
            new EfCoreServiceSettingStore<IdentityDbContext>(
                serviceProvider.GetRequiredService<IDbContextFactory<IdentityDbContext>>()));

        services.AddScoped<IServiceSettingUpdateTransaction>(serviceProvider =>
            new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(
                serviceProvider.GetRequiredService<IdentityDbContext>()));
        services.AddScoped<ServiceSettingUpdateService>(serviceProvider => new ServiceSettingUpdateService(
            InstallationStores.ServiceId,
            serviceProvider.GetRequiredService<ServiceSettingDefinitionRegistry>(),
            serviceProvider.GetRequiredService<IServiceSettingUpdateTransaction>(),
            serviceProvider.GetRequiredService<IServiceSettingRootKeySource>()));

        services.AddServiceMantleSettingSnapshots();
        return services;
    }
}
