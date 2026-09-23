using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ServiceMantle;
using ServiceMantle.AspNetCore;
using ServiceMantle.Configuration;
using ServiceMantle.Database.PostgreSql;
using ServiceMantle.Database.Sqlite;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using SignaCore.Host.HealthChecks;
using SignaCore.Host.Http;
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
/// normal host composes the full ServiceMantle pipeline (<c>UseServiceMantlePipeline</c>) with the
/// shared management session capabilities. The installation state, the business database,
/// authentication, and Serilog remain owned by SignaCore. The ServiceMantle request log scope adds
/// its own ServiceName, ServiceVersion, and InstanceId fields; the existing global Serilog
/// enrichment is intentionally left unchanged.
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
    /// <returns>The builder the normal host extends with its own shared capabilities.</returns>
    internal static ServiceMantleBuilder AddSignaCoreServiceMantle(
        this IServiceCollection services,
        string? bootstrapFilePath = null)
    {
        var builder = services.AddServiceMantle(
            ServiceId.Parse(ServiceIdentifier),
            InstanceId.Parse($"{ServiceIdentifier}-{Guid.NewGuid():N}"),
            bootstrapFilePath);
        builder.AddBootstrapDatabaseProvider<PostgreSqlBootstrapDatabaseProvider>();
        builder.AddBootstrapDatabaseProvider<SqliteBootstrapDatabaseProvider>();
        return builder;
    }

    /// <summary>
    /// Registers the shared ServiceMantle capabilities only the normal host owns: the fixed health
    /// endpoint capability, the signing-key readiness contributor, the product-specific sensitive
    /// request Header set, the security response headers, and the shared rate-limit policies.
    /// </summary>
    /// <remarks>
    /// The health endpoints this registers are mapped once by the normal host through
    /// <c>MapServiceMantleHealthEndpoints</c>, which owns <c>/health/live</c>, <c>/health/ready</c>,
    /// and the <c>/health</c> readiness alias; the signing-key contributor is the live readiness
    /// authority behind both readiness routes. This must run before
    /// <c>AddIdentityInfrastructure</c>: the host composes its own rate limiter afterwards, and the
    /// host's rejection contract — the JSON body locked by <c>HostRejectionWriteCancellationTests</c>
    /// — stays the effective one for every policy, including the ServiceMantle-named policies the
    /// session entries reference. The Bootstrap and Setup hosts deliberately do not call this:
    /// neither registers <see cref="IKeyManager"/> nor serves an <c>X-Admin-AppSecret</c> endpoint,
    /// and the readiness validator resolves every contributor when the host starts.
    /// </remarks>
    internal static ServiceMantleBuilder AddSignaCoreSharedHttpCapabilities(
        this ServiceMantleBuilder builder)
    {
        builder.AddServiceMantleHealthEndpoints();
        builder.AddServiceReadinessContributor<SigningKeyReadinessContributor>();
        // The gateway application secret is a SignaCore contract, so it is registered through the
        // shared extension point rather than hardcoded in the shared library's built-in set.
        builder.AddSensitiveHeaders(options => options.DeniedHeaderNames = [IdentityHeaders.AppSecret]);
        // The composed pipeline and the management session entries require the security response
        // headers and the shared rate-limit policies; both stay ahead of the host's own rate limiter
        // so its locked rejection contract keeps serving every named policy.
        builder.AddSecurityResponseHeaders();
        builder.AddRateLimiting();
        return builder;
    }

    /// <summary>
    /// Registers the shared ServiceMantle setting stack in the normal host: the product
    /// definitions, the composite validator, the EF Core single-aggregate store, the transactional
    /// update path, the root key source, and the snapshot/query services.
    /// </summary>
    /// <remarks>
    /// This is a parallel addition: the legacy <c>system_settings</c> read path of the admin
    /// console and the legacy import stay untouched. The update transaction and update service are
    /// scoped over the same scoped <c>IdentityDbContext</c> the host already registers; the store
    /// owns its contexts through the factory. When the bootstrap phase pre-registered its activated
    /// <see cref="ServiceSettingCurrentSnapshotAccessor"/> instance, the snapshot registrations
    /// adopt that instance instead of building a second one.
    /// </remarks>
    internal static IServiceCollection AddSignaCoreSharedSettings(
        this IServiceCollection services,
        DatabaseOptions databaseOptions,
        bool isDevelopment)
    {
        services.AddSignaCoreSharedSettingUpdates(isDevelopment);

        // The shared store creates and releases its own contexts; both registrations use the same
        // provider options as the scoped business context.
        services.AddDbContextFactory<IdentityDbContext>(
            options => options.UseIdentityDatabase(databaseOptions));
        services.AddSingleton<IServiceSettingStore>(serviceProvider =>
            new EfCoreServiceSettingStore<IdentityDbContext>(
                serviceProvider.GetRequiredService<IDbContextFactory<IdentityDbContext>>()));

        services.AddServiceMantleSettingSnapshots();
        return services;
    }

    /// <summary>
    /// Registers the transactional shared setting update path without any snapshot or store
    /// services: the product definitions, the composite validator, the definition registry, the
    /// root key source, and the scoped update transaction and update service over the caller's
    /// scoped <c>IdentityDbContext</c>.
    /// </summary>
    /// <remarks>
    /// The PendingSetup host registers exactly this so first-run completion writes the shared
    /// aggregate through the same update service the normal host composes, while nothing resolves
    /// a snapshot loader before a snapshot can exist. The context registration must disable the
    /// retrying execution strategy — the completion transaction is caller-opened and may be
    /// attempted exactly once.
    /// </remarks>
    internal static IServiceCollection AddSignaCoreSharedSettingUpdates(
        this IServiceCollection services,
        bool isDevelopment)
    {
        services.AddSingleton<IServiceSettingDefinitionProvider, ServiceSettingDefinitions>();
        services.AddSingleton<IServiceSettingCompositeValidator>(_ =>
            new SignaCoreSettingCompositeValidator(isDevelopment));
        services.AddSingleton<IServiceSettingRootKeySource, MasterKeyRootKeySource>();
        services.TryAddSingleton(serviceProvider => new ServiceSettingDefinitionRegistry(
            serviceProvider.GetServices<IServiceSettingDefinitionProvider>(),
            serviceProvider.GetServices<IServiceSettingCompositeValidator>()));

        services.AddScoped<IServiceSettingUpdateTransaction>(serviceProvider =>
            new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(
                serviceProvider.GetRequiredService<IdentityDbContext>()));
        services.AddScoped<ServiceSettingUpdateService>(serviceProvider => new ServiceSettingUpdateService(
            InstallationStores.ServiceId,
            serviceProvider.GetRequiredService<ServiceSettingDefinitionRegistry>(),
            serviceProvider.GetRequiredService<IServiceSettingUpdateTransaction>(),
            serviceProvider.GetRequiredService<IServiceSettingRootKeySource>()));
        return services;
    }
}
