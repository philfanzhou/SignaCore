using Microsoft.EntityFrameworkCore;
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
    /// This is a parallel addition that maps no route: the <c>/health/live</c>,
    /// <c>/health/ready</c>, and <c>/health</c> endpoints stay owned by
    /// <see cref="SigningKeysHealthCheck"/> and the ASP.NET Core health-check stack, so the
    /// contributor stays dormant until the endpoint switch replaces them. The startup validators the
    /// registrations add still run, which is what proves the contributor and the Header set are
    /// wired correctly. This must run before <c>AddIdentityInfrastructure</c>: the host composes its
    /// own rate limiter afterwards, and the host's rejection contract — the JSON body locked by
    /// <c>HostRejectionWriteCancellationTests</c> — stays the effective one for every policy,
    /// including the ServiceMantle-named policies the session entries reference. The Bootstrap and
    /// Setup hosts deliberately do not call this: neither registers <see cref="IKeyManager"/> nor
    /// serves an <c>X-Admin-AppSecret</c> endpoint, and the readiness validator resolves every
    /// contributor when the host starts.
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
