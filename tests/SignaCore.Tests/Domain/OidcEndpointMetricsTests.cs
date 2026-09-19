using System.Diagnostics.Metrics;
using Moq;
using SignaCore.Domain;
using Xunit;

namespace SignaCore.Tests.Domain;

/// <summary>
/// The contract of the interactive OIDC endpoint-class metrics (issue #305): every label comes
/// from a closed set — the fixed endpoint names, the closed outcome/reason vocabulary, and an
/// optional registered client id — the recorded series stay bounded under arbitrary inputs, and
/// a recording failure never escapes the recorder.
/// </summary>
public sealed class OidcEndpointMetricsTests
{
    private static readonly string[] ClosedOutcomeVocabulary =
    [
        "success",
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "invalid_scope",
        "unsupported_grant_type",
        "replay",
        "server_error",
        "invalid_token",
        "insufficient_scope",
        AuthMetrics.RateLimitedOutcome
    ];

    private static readonly string[] ClosedEndpointVocabulary =
    [
        AuthMetrics.OidcMetricEndpoints.Token,
        AuthMetrics.OidcMetricEndpoints.Refresh,
        AuthMetrics.OidcMetricEndpoints.UserInfo,
        AuthMetrics.OidcMetricEndpoints.LogoutPrepare,
        AuthMetrics.OidcMetricEndpoints.LogoutComplete
    ];

    [Fact]
    public void OutcomeAndDuration_ReachTheSignaCoreMeter()
    {
        var (metrics, listener, outcomes, durations) = Listen();

        metrics.RecordOidcEndpointOutcome(
            AuthMetrics.OidcMetricEndpoints.Token, "success", "registered-app");
        metrics.RecordOidcEndpointDuration(AuthMetrics.OidcMetricEndpoints.Token, 12.5);

        Assert.Equal(
            [("token", "success", "registered-app", 1L)],
            outcomes.Select(o => (o.Endpoint, o.Outcome, o.ClientId, o.Value)).ToArray());
        Assert.Equal(
            [("token", 12.5)],
            durations.Select(d => (d.Endpoint, d.Value)).ToArray());
    }

    [Fact]
    public void TheLabelUniverse_StaysWithinTheClosedAllowlist()
    {
        var (metrics, listener, outcomes, durations) = Listen();

        // Every endpoint class, every documented outcome, with and without the client label.
        foreach (var endpoint in ClosedEndpointVocabulary)
        {
            foreach (var outcome in ClosedOutcomeVocabulary)
            {
                metrics.RecordOidcEndpointOutcome(endpoint, outcome, "registered-app");
                metrics.RecordOidcEndpointOutcome(endpoint, outcome);
                metrics.RecordOidcEndpointDuration(endpoint, 1.0);
            }
        }

        // The only label names that may ever appear.
        Assert.All(
            outcomes.SelectMany(o => o.LabelNames).Concat(durations.SelectMany(d => d.LabelNames)),
            name => Assert.Contains(name, new[] { "endpoint", "outcome", "client_id" }));
        // Forbidden names never appear (DF-11/DF-13).
        var forbidden = new[]
        {
            "account_id", "session_id", "code_id", "family_id", "request_id", "correlation_id",
            "uri", "username", "ip", "claim", "token", "handle", "state", "nonce"
        };
        Assert.All(
            outcomes.SelectMany(o => o.LabelNames).Concat(durations.SelectMany(d => d.LabelNames)),
            name => Assert.DoesNotContain(name, forbidden));
    }

    [Fact]
    public void TheSeriesCount_IsBoundedByTheClosedSets()
    {
        var (metrics, listener, outcomes, _) = Listen();

        // Hundreds of calls over the whole vocabulary: the distinct label tuples are bounded by
        // the product of the closed sets, not by the number of calls.
        foreach (var sequence in Enumerable.Range(0, 500))
        {
            var endpoint = ClosedEndpointVocabulary[sequence % ClosedEndpointVocabulary.Length];
            var outcome = ClosedOutcomeVocabulary[sequence % ClosedOutcomeVocabulary.Length];
            metrics.RecordOidcEndpointOutcome(endpoint, outcome, "registered-app");
            metrics.RecordOidcEndpointOutcome(endpoint, outcome);
        }

        var distinct = outcomes
            .Select(o => (o.Endpoint, o.Outcome, o.ClientId))
            .Distinct()
            .Count();
        Assert.Equal(ClosedEndpointVocabulary.Length * ClosedOutcomeVocabulary.Length * 2, distinct);
    }

    private static (AuthMetrics Metrics, MeterListener Listener, List<(string Endpoint, string Outcome, string? ClientId, long Value, IEnumerable<string> LabelNames)> Outcomes, List<(string Endpoint, double Value, IEnumerable<string> LabelNames)> Durations) Listen()
    {
        var factory = new MeterFactory();
        var metrics = new AuthMetrics(factory);
        var outcomes = new List<(string, string, string?, long, IEnumerable<string>)>();
        var durations = new List<(string, double, IEnumerable<string>)>();
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == "SignaCore"
                    && (instrument.Name == "oidc.endpoint.outcome" || instrument.Name == "oidc.endpoint.duration"))
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<int>((instrument, value, tags, state) =>
        {
            var endpoint = string.Empty;
            var outcome = string.Empty;
            string? clientId = null;
            var names = new List<string>();
            foreach (var tag in tags)
            {
                names.Add(tag.Key);
                if (tag.Key == "endpoint") endpoint = tag.Value?.ToString() ?? string.Empty;
                if (tag.Key == "outcome") outcome = tag.Value?.ToString() ?? string.Empty;
                if (tag.Key == "client_id") clientId = tag.Value?.ToString();
            }

            outcomes.Add((endpoint, outcome, clientId, value, names));
        });
        listener.SetMeasurementEventCallback<double>((instrument, value, tags, state) =>
        {
            var endpoint = string.Empty;
            var names = new List<string>();
            foreach (var tag in tags)
            {
                names.Add(tag.Key);
                if (tag.Key == "endpoint") endpoint = tag.Value?.ToString() ?? string.Empty;
            }

            durations.Add((endpoint, value, names));
        });
        listener.Start();
        return (metrics, listener, outcomes, durations);
    }

    private sealed class MeterFactory : IMeterFactory
    {
        private readonly List<Meter> _meters = [];

        public Meter Create(MeterOptions options)
        {
            var meter = new Meter(options.Name);
            _meters.Add(meter);
            return meter;
        }

        public void Dispose() => _meters.ForEach(meter => meter.Dispose());
    }
}
