using Microsoft.Extensions.DependencyInjection;
using ServiceMantle;
using ServiceMantle.Audit;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;

namespace SignaCore.ReferenceBff.Database;

/// <summary>
/// The ServiceMantle identity of this reference sample. It is deliberately not the product's
/// <c>signacore</c> service id: the BFF's independent database tracks its own installation.
/// </summary>
public static class ReferenceBffServiceMantle
{
    /// <summary>The fixed service id under which the BFF's installation state is persisted.</summary>
    public const string ServiceIdValue = "reference-bff";

    /// <summary>The parsed service id for store calls.</summary>
    public static ServiceId ServiceId => ServiceId.Parse(ServiceIdValue);
}

/// <summary>
/// Minimal scoped wiring for the shared ServiceMantle stores over the BFF's own context. Both
/// stores resolve the same caller-owned scoped <see cref="ReferenceBffDbContext"/>, so a staged
/// audit record and an installation write always share one unit of work and one transaction.
/// </summary>
/// <remarks>
/// This extension registers stores only. It does not register or configure a
/// <see cref="ReferenceBffDbContext"/> provider, it never opens a connection, and it never
/// initializes an installation row or an administrator binding: the caller owns the context
/// lifetime (and, for a first installation, the shared initialization save contract). Runtime
/// wiring of the context itself is a later slice; tests provide the context explicitly.
/// </remarks>
public static class ReferenceBffServiceMantleServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IServiceInstallationStore"/> and <see cref="IManagementAuditWriter"/> as
    /// scoped services over the scoped <see cref="ReferenceBffDbContext"/> the caller registered.
    /// </summary>
    public static IServiceCollection AddReferenceBffServiceMantleStores(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<IServiceInstallationStore, EfCoreServiceInstallationStore<ReferenceBffDbContext>>();
        services.AddScoped<IManagementAuditWriter, EfCoreManagementAuditWriter<ReferenceBffDbContext>>();
        return services;
    }
}
