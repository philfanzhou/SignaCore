using System.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ServiceMantle.Configuration;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;

namespace SignaCore.Host.Management;

/// <summary>
/// The consumer-owned commit boundary behind the shared management setting update endpoint.
/// <para>
/// Per the shared contract, the update runs in a fresh asynchronous scope with its own
/// <see cref="IdentityDbContext"/> — built with the retrying execution strategy disabled, because
/// the serializable transaction here is caller-opened and must be attempted exactly once — and is
/// never resolved from the request's scoped business context. The shared update service validates
/// the whole candidate, re-protects sensitive values, and stages the aggregate plus the key-only
/// audit rows inside this transaction; Applied is returned only after the commit completed. Every
/// failure or cancellation rolls the transaction back and discards the scope without retrying.
/// </para>
/// </summary>
internal static class ManagementSettingUpdateExecutor
{
    public static async ValueTask<ServiceSettingUpdateResult> ExecuteAsync(
        HttpContext httpContext,
        ServiceSettingUpdateCommand command,
        CancellationToken cancellationToken)
    {
        // A fresh scope per request: the shared registry and the root-key source are resolved from
        // it, but the update transaction is bound to this executor's own context — resolving the
        // scoped update service would bind the update to the host's retrying business context.
        var scopeFactory = httpContext.RequestServices.GetRequiredService<IServiceScopeFactory>();
        await using (var scope = scopeFactory.CreateAsyncScope())
        {
            var services = scope.ServiceProvider;
            var databaseOptions = services.GetRequiredService<DatabaseOptions>();
            var contextOptionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            contextOptionsBuilder.UseIdentityDatabase(databaseOptions, enableRetryOnFailure: false);
            var contextOptions = contextOptionsBuilder.Options;

            var logger = services.GetRequiredService<ILoggerFactory>()
                .CreateLogger("SignaCore.Host.Management.ManagementSettingUpdateExecutor");
            try
            {
                await using (var db = new IdentityDbContext(contextOptions))
                await using (var transaction = await db.Database.BeginTransactionAsync(
                                 IsolationLevel.Serializable,
                                 cancellationToken))
                {
                    var updateService = new ServiceSettingUpdateService(
                        InstallationStores.ServiceId,
                        services.GetRequiredService<ServiceSettingDefinitionRegistry>(),
                        new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(db),
                        services.GetRequiredService<IServiceSettingRootKeySource>());

                    var result = await updateService.UpdateAsync(command, cancellationToken);
                    if (!result.Succeeded)
                    {
                        // The shared transaction already restored its savepoint; disposing the
                        // transaction rolls the attempt back whole.
                        return result;
                    }

                    await transaction.CommitAsync(cancellationToken);
                    logger.LogInformation(
                        "Settings updated to version {Version}: {ChangeCount} change(s)",
                        result.Version,
                        command.Changes.Count);
                    return result;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // The caller's own cancellation is authoritative wherever it is observed; the
                // shared endpoint classifies it. The transaction was disposed uncommitted.
                throw;
            }
            catch
            {
                // Database, cryptographic, and provider failures carry constraint names and values
                // in their messages; the endpoint reports only the fixed safe failure.
                return ServiceSettingUpdateResult.Failure(ServiceSettingUpdateStatus.StorageFailed);
            }
        }
    }
}
