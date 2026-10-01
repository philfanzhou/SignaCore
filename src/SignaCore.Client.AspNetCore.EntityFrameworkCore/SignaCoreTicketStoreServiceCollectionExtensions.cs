using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SignaCore.Client.AspNetCore.EntityFrameworkCore;

/// <summary>
/// The registration entry of the persistent ticket store. It replaces whatever
/// <see cref="global::SignaCore.Client.AspNetCore.ITicketStore"/> registration exists — including
/// the default in-process store <c>AddSignaCoreHostedLogin</c> installs — so the call order
/// against the package's own registration does not matter.
/// </summary>
public static class SignaCoreTicketStoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers the persistent ticket store backed by the consumer's
    /// <typeparamref name="TDbContext"/>. The context must map
    /// <see cref="SignaCoreSessionTicketEntity"/> through
    /// <see cref="SignaCoreTicketStoreModelBuilderExtensions.ConfigureSignaCoreTicketStore"/>, and
    /// the consumer generates and applies the migration for its provider: this package never
    /// creates or executes migrations.
    /// </summary>
    /// <typeparam name="TDbContext">The consumer's <see cref="DbContext"/>.</typeparam>
    /// <param name="services">The application's service collection.</param>
    public static IServiceCollection AddSignaCoreEntityFrameworkTicketStore<TDbContext>(
        this IServiceCollection services)
        where TDbContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        // RemoveAll keeps the registration authoritative whether this runs before or after
        // AddSignaCoreHostedLogin's TryAddSingleton<ITicketStore>.
        services.RemoveAll<global::SignaCore.Client.AspNetCore.ITicketStore>();
        services.TryAddSingleton<EntityFrameworkTicketStore<TDbContext>>();
        services.TryAddSingleton<global::SignaCore.Client.AspNetCore.ITicketStore>(
            static services => services.GetRequiredService<EntityFrameworkTicketStore<TDbContext>>());
        return services;
    }
}
