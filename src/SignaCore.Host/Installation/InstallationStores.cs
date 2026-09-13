using ServiceMantle;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;

namespace SignaCore.Host.Installation;

/// <summary>
/// The single place that binds SignaCore's installation identity to the shared ServiceMantle
/// installation stores. The service id is the durable installation identity; the setup code
/// lifetime keeps SignaCore's documented 24-hour validity instead of the shared default.
/// </summary>
internal static class InstallationStores
{
    internal const string ServiceIdValue = ServiceMantleComposition.ServiceIdentifier;

    internal static ServiceId ServiceId => ServiceId.Parse(ServiceIdValue);

    /// <summary>SignaCore's documented setup code validity, also the shared maximum.</summary>
    internal static readonly SetupCodeLifetime SetupCodeLifetime =
        SetupCodeLifetime.Create(TimeSpan.FromHours(24));

    internal static EfCoreServiceInstallationStore<IdentityDbContext> CreateInstallationStore(
        IdentityDbContext db) => new(db);

    internal static EfCoreServiceSetupCodeStore<IdentityDbContext> CreateSetupCodeStore(
        IdentityDbContext db) => new(db, lifetime: SetupCodeLifetime);
}
