using Microsoft.Extensions.Hosting;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The periodic sweep behind the ticket, pending-sign-in, and logout-return stores: expired
/// entries are reclaimed on a timer, not only when a request happens to present their key again.
/// </summary>
internal sealed class TicketStoreCleanupService(
    ITicketStore ticketStore,
    PendingSignInStore pendingSignInStore,
    LogoutReturnStateStore logoutReturnStateStore) : BackgroundService
{
    /// <summary>The sweep cadence of all three stores.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(15);

    private readonly ITicketStore _ticketStore = ticketStore;
    private readonly PendingSignInStore _pendingSignInStore = pendingSignInStore;
    private readonly LogoutReturnStateStore _logoutReturnStateStore = logoutReturnStateStore;

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                _ticketStore.RemoveExpired(stoppingToken);
                _pendingSignInStore.RemoveExpired(stoppingToken);
                _logoutReturnStateStore.RemoveExpired(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown; there is nothing left to sweep.
        }
    }
}
