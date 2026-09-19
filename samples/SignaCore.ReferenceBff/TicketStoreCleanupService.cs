namespace SignaCore.ReferenceBff;

/// <summary>
/// The periodic sweep behind <see cref="MemoryTicketStore"/>: expired tickets are reclaimed on a
/// timer, not only when a request happens to present their key again.
/// </summary>
public sealed class TicketStoreCleanupService(MemoryTicketStore store) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(15);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                store.RemoveExpired();
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown; there is nothing left to sweep.
        }
    }
}
