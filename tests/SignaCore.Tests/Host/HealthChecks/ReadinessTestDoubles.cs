using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ServiceMantle.AspNetCore;
using ServiceMantle.AspNetCore.Health;
using ServiceMantle.Health;
using SignaCore.Host;

namespace SignaCore.Tests.Host.HealthChecks;

/// <summary>
/// A readiness contributor the tests script directly: it records how often it ran so an evaluation
/// can prove a rejection, a failure, or an exhausted budget did not short-circuit the sequence.
/// </summary>
internal sealed class ScriptedReadinessContributor(
    int order,
    Func<ServiceHealthSnapshot, CancellationToken, ValueTask<ServiceReadinessContributorResult>> evaluate)
    : IServiceReadinessContributor
{
    private int calls;

    public int Calls => Volatile.Read(ref calls);

    public int Order => order;

    public ValueTask<ServiceReadinessContributorResult> EvaluateAsync(
        ServiceHealthSnapshot snapshot,
        CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref calls);
        return evaluate(snapshot, cancellationToken);
    }
}

/// <summary>Returns one fixed snapshot, or nothing at all when the source is meant to be absent.</summary>
internal sealed class StubSnapshotSource(ServiceHealthSnapshot? snapshot) : IServiceHealthSnapshotSource
{
    public ValueTask<ServiceHealthSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(snapshot!);
}

/// <summary>
/// An advanceable <see cref="TimeProvider"/> that pins how the shared contributor budget is spent.
/// Only the members the combiner touches are implemented: the timestamp pair that measures elapsed
/// budget, and one-shot timers driven by <see cref="Advance"/> instead of by the wall clock.
/// </summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private readonly object gate = new();
    private readonly List<ManualTimer> timers = [];
    private DateTimeOffset utcNow = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow()
    {
        lock (gate)
        {
            return utcNow;
        }
    }

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp()
    {
        lock (gate)
        {
            return utcNow.UtcTicks;
        }
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        ArgumentNullException.ThrowIfNull(callback);
        var timer = new ManualTimer(this, callback, state);
        lock (gate)
        {
            timer.DueAt = Due(dueTime);
            timers.Add(timer);
        }

        return timer;
    }

    /// <summary>Moves the virtual clock forward and fires every timer that becomes due.</summary>
    public void Advance(TimeSpan delta)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(delta, TimeSpan.Zero);
        lock (gate)
        {
            utcNow += delta;
        }

        while (true)
        {
            ManualTimer? due;
            lock (gate)
            {
                due = timers.FirstOrDefault(timer => timer.DueAt is { } dueAt && dueAt <= utcNow);
                if (due is not null)
                {
                    due.DueAt = null;
                }
            }

            if (due is null)
            {
                return;
            }

            due.Invoke();
        }
    }

    private DateTimeOffset? Due(TimeSpan dueTime) =>
        dueTime == Timeout.InfiniteTimeSpan ? null : utcNow + dueTime;

    private void Reschedule(ManualTimer timer, TimeSpan dueTime)
    {
        lock (gate)
        {
            timer.DueAt = Due(dueTime);
        }
    }

    private void Remove(ManualTimer timer)
    {
        lock (gate)
        {
            timer.DueAt = null;
            timers.Remove(timer);
        }
    }

    private sealed class ManualTimer(ManualTimeProvider provider, TimerCallback callback, object? state) : ITimer
    {
        internal DateTimeOffset? DueAt { get; set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            provider.Reschedule(this, dueTime);
            return true;
        }

        public void Dispose() => provider.Remove(this);

        public ValueTask DisposeAsync()
        {
            provider.Remove(this);
            return ValueTask.CompletedTask;
        }

        internal void Invoke() => callback(state);
    }
}

/// <summary>Builds the shared ServiceMantle container the readiness and Header tests drive.</summary>
internal static class ReadinessComposition
{
    /// <summary>
    /// Registers the same capabilities the normal host registers, optionally extending the builder
    /// so a negative case can add a conflicting registration.
    /// </summary>
    internal static IServiceCollection Configure(
        Action<IServiceCollection, ServiceMantleBuilder>? extend = null,
        bool sharedHttpCapabilities = true)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var builder = services.AddSignaCoreServiceMantle();
        if (sharedHttpCapabilities)
        {
            builder.AddSignaCoreSharedHttpCapabilities();
        }

        extend?.Invoke(services, builder);
        return services;
    }

    internal static ServiceProvider Build(
        Action<IServiceCollection, ServiceMantleBuilder>? extend = null,
        bool sharedHttpCapabilities = true) =>
        Configure(extend, sharedHttpCapabilities).BuildServiceProvider();

    /// <summary>Runs every startup validator the registrations added, exactly as the host does.</summary>
    internal static async Task StartValidatorsAsync(
        IServiceProvider provider,
        CancellationToken cancellationToken = default)
    {
        foreach (var hosted in provider.GetServices<IHostedService>())
        {
            await hosted.StartAsync(cancellationToken);
        }
    }
}
