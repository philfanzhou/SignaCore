using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ServiceMantle.Configuration;
using ServiceMantle.Database.PostgreSql;
using ServiceMantle.Database.Sqlite;
using ServiceMantle.Persistence.Relational.Stores;
using ServiceMantle.Web;
using ServiceMantle;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using SignaCore.Host.HealthChecks;
using SignaCore.Host.Http;
using SignaCore.Host.Installation;
using SignaCore.Host.Management;

namespace SignaCore.Host;

/// <summary>
/// The minimal ServiceMantle composition shared by the Bootstrap, Setup, and normal hosts.
/// </summary>
/// <remarks>
/// The host identity and the shared bootstrap file store are registered: the file lifecycle
/// (locate, read, create, replace) belongs to the shared store, with the PostgreSQL and SQLite
/// bootstrap providers registered so the store resolves both. All three hosts use the shared HTTP pipeline
/// (<c>UseServiceMantlePipeline</c>); the normal host additionally composes the
/// shared management session capabilities. The installation state, the business database, and
/// authentication remain owned by SignaCore. Logging is the ServiceMantle Serilog pipeline
/// composed by <see cref="Logging.SignaCoreLogging"/>; the ServiceMantle request log scope adds the
/// ServiceName, ServiceVersion, and InstanceId fields.
/// </remarks>
internal static class ServiceMantleComposition
{
    internal const string ServiceIdentifier = "signacore";

    /// <summary>
    /// Registers the ServiceMantle host identity and the shared bootstrap file store. The instance
    /// id is generated once per host build (<c>signacore-</c> plus a GUID in N format) and is used
    /// as non-secret runtime metadata; it is not a persistent identity. The service version is
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
            InstanceId.CreateRandom(ServiceId.Parse(ServiceIdentifier)),
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
    /// The default update service is scoped over the host's <c>IdentityDbContext</c>; management
    /// recovery owns a fresh context and per-call baseline. The store owns its contexts through
    /// the factory. Snapshot registrations adopt the bootstrap-activated runtime accessor, while
    /// management queries use an independent tolerant loader/accessor and safe shared projection.
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
        // Management observes a complete tolerant snapshot on an isolated accessor. Refreshing
        // the settings page must never publish into the bootstrap/runtime authority.
        services.AddSingleton(serviceProvider => new ManagementSettingQuerySnapshot(
            serviceProvider.GetRequiredService<IServiceSettingStore>(),
            serviceProvider.GetRequiredService<IServiceSettingRootKeySource>(), isDevelopment));
        services.Replace(ServiceDescriptor.Singleton(serviceProvider =>
            serviceProvider.GetRequiredService<ManagementSettingQuerySnapshot>().Query));
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
        // Setup and default updates enforce optional telemetry rules. Management recovery builds
        // a per-call registry from its transaction baseline; startup and query loads are tolerant.
        services.AddSingleton<IServiceSettingCompositeValidator>(_ =>
            new SignaCoreSettingCompositeValidator(isDevelopment, validateManagementUpdateRules: true));
        services.AddSingleton<IServiceSettingRootKeySource, MasterKeyRootKeySource>();
        services.TryAddSingleton(_ => SharedSettingComposition.CreateRegistry(
            isDevelopment, validateManagementUpdateRules: true));

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
