using System.Diagnostics.Metrics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;

namespace SignaCore.Host.Metrics;

/// <summary>
/// The five bounded retention gauges of the interactive OIDC artifacts (issue #305): login
/// continuations, identity sessions, authorization codes, logout requests, and interactive
/// refresh family members. Each is an observable gauge sampled at collection time from the
/// database — a sampled population count, not a live claim about any instant — and carries only
/// the closed database-provider label. A sampling failure observes nothing: gauges never change
/// protocol behavior.
/// </summary>
public sealed class OidcRetentionGauges
{
    public const string ProviderLabel = "provider";

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly string _provider;

    public OidcRetentionGauges(IMeterFactory meterFactory, IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
        _provider = ResolveProvider();
        var meter = meterFactory.Create("SignaCore");
        meter.CreateObservableGauge(
            "oidc.retention.continuation",
            () => ObserveCount("oidc.retention.continuation", db => db.AuthorizationRequests.CountAsync()),
            "count",
            "Retained login continuations");
        meter.CreateObservableGauge(
            "oidc.retention.identity_session",
            () => ObserveCount("oidc.retention.identity_session", db => db.IdentitySessions.CountAsync()),
            "count",
            "Retained identity sessions");
        meter.CreateObservableGauge(
            "oidc.retention.authorization_code",
            () => ObserveCount("oidc.retention.authorization_code", db => db.AuthorizationCodes.CountAsync()),
            "count",
            "Retained authorization codes");
        meter.CreateObservableGauge(
            "oidc.retention.logout_request",
            () => ObserveCount("oidc.retention.logout_request", db => db.LogoutRequests.CountAsync()),
            "count",
            "Retained logout requests");
        meter.CreateObservableGauge(
            "oidc.retention.interactive_family",
            () => ObserveCount(
                "oidc.retention.interactive_family",
                db => db.RefreshTokens.CountAsync(token => token.IdentitySessionId != null)),
            "count",
            "Retained interactive refresh family members");
    }

    /// <summary>The closed provider label of every gauge: the configured database engine.</summary>
    public string Provider => _provider;

    private IEnumerable<Measurement<long>> ObserveCount(
        string name,
        Func<IdentityDbContext, Task<int>> count)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var value = count(dbContext).GetAwaiter().GetResult();
            return [new Measurement<long>(value, new KeyValuePair<string, object?>(ProviderLabel, _provider))];
        }
        catch (Exception)
        {
            // A failed sample observes nothing; the gauge never disturbs behavior.
            return [];
        }
    }

    private string ResolveProvider()
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            return dbContext.Database.ProviderName switch
            {
                "Microsoft.EntityFrameworkCore.Sqlite" => "sqlite",
                "Npgsql.EntityFrameworkCore.PostgreSQL" => "postgresql",
                _ => "other"
            };
        }
        catch (Exception)
        {
            return "other";
        }
    }
}
