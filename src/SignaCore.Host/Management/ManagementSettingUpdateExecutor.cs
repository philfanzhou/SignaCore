using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using ServiceMantle.Configuration;
using ServiceMantle.Persistence.Relational.Stores;
using SignaCore.Database;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using System.Data;

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
            var concurrency = new SerializationConflictInterceptor();
            var contextOptionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            contextOptionsBuilder.UseIdentityDatabase(databaseOptions, enableRetryOnFailure: false);
            contextOptionsBuilder.AddInterceptors(concurrency);
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
                    var rootKey = services.GetRequiredService<IServiceSettingRootKeySource>();
                    var recovery = new ManagementSettingRecovery(
                        new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(db), rootKey,
                        services.GetRequiredService<IHostEnvironment>().IsDevelopment(), command);
                    var updateService = new ServiceSettingUpdateService(
                        InstallationStores.ServiceId, recovery.Registry, recovery, rootKey);

                    var result = await updateService.UpdateAsync(command, cancellationToken);
                    if (!result.Succeeded)
                    {
                        // The shared transaction already restored its savepoint; disposing the
                        // transaction rolls the attempt back whole.
                        return result.Status == ServiceSettingUpdateStatus.StorageFailed
                            && concurrency.SerializationFailed
                            ? ServiceSettingUpdateResult.Failure(ServiceSettingUpdateStatus.VersionConflict)
                            : result;
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
            catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.SerializationFailure)
            {
                return ServiceSettingUpdateResult.Failure(ServiceSettingUpdateStatus.VersionConflict);
            }
            catch
            {
                // Database, cryptographic, and provider failures carry constraint names and values
                // in their messages; the endpoint reports only the fixed safe failure.
                return ServiceSettingUpdateResult.Failure(ServiceSettingUpdateStatus.StorageFailed);
            }
        }
    }

    // The shared EF adapter closes provider errors into StorageFailed. Keep only the non-secret
    // serializable conflict category on this caller-owned context so competing writes get the
    // existing 409 without replaying the transaction or exposing exception details.
    private sealed class SerializationConflictInterceptor : SaveChangesInterceptor
    {
        internal bool SerializationFailed { get; private set; }

        public override Task SaveChangesFailedAsync(
            DbContextErrorEventData eventData, CancellationToken cancellationToken = default)
        {
            for (var failure = eventData.Exception; failure is not null; failure = failure.InnerException)
                if (failure is PostgresException { SqlState: PostgresErrorCodes.SerializationFailure })
                    SerializationFailed = true;
            return Task.CompletedTask;
        }
    }
}
