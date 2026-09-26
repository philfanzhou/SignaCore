using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;
using static SignaCore.Tests.Integration.OidcDatabaseTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>Request-local secrets and captured carriers never become assertion arguments.</summary>
internal sealed class OidcCanaryScan
{
    private readonly List<(string Kind, string Value)> _canaries = [];
    private readonly ConcurrentQueue<(string Carrier, string Text)> _surfaces = new();
    private readonly HashSet<(string Table, string Column, string Row, string Value)> _snapshots = [];

    public string Add(string kind, string value)
    {
        Assert.False(string.IsNullOrEmpty(value), "A canary was empty.");
        if (!_canaries.Contains((kind, value))) _canaries.Add((kind, value));
        return value;
    }

    public string New(string kind) => Add(kind, kind + "-" + Guid.NewGuid().ToString("N"));
    public void Capture(string carrier, string text) => _surfaces.Enqueue((carrier, text));
    public void AllowSnapshot(string table, string column, Guid row, string value) =>
        _snapshots.Add((table, column, row.ToString(), value));

    public IReadOnlyList<string> Violations()
    {
        var failures = new HashSet<string>();
        foreach (var (carrier, text) in _surfaces)
        for (var i = 0; i < _canaries.Count; i++)
            if (text.Contains(_canaries[i].Value, StringComparison.Ordinal))
                failures.Add($"canary #{i}: {carrier}");
        return failures.Order().ToArray();
    }
    public void AssertClean() => Assert.Empty(Violations());

    public async Task ScanDatabaseAsync(Harness harness)
    {
        await using var connection = await harness.OpenAsync();
        var tables = new List<string>();
        await using (var list = new NpgsqlCommand("SELECT tablename FROM pg_tables WHERE schemaname = 'public'", connection))
        await using (var reader = await list.ExecuteReaderAsync(Ct))
            while (await reader.ReadAsync(Ct)) tables.Add(reader.GetString(0));
        var seen = new HashSet<(string Table, string Column, string Row, string Value)>();
        foreach (var table in tables)
        {
            // Identifiers come only from PostgreSQL's catalog, quoted independently of values.
            var quoted = new NpgsqlCommandBuilder().QuoteIdentifier(table);
            await using var command = new NpgsqlCommand($"SELECT row_to_json(t)::text FROM {quoted} t", connection);
            await using var reader = await command.ExecuteReaderAsync(Ct);
            while (await reader.ReadAsync(Ct))
            {
                using var json = JsonDocument.Parse(reader.GetString(0));
                var row = json.RootElement.TryGetProperty("id", out var id) ? id.ToString() :
                    table == "oidc_rate_limit_buckets" ? json.RootElement.GetProperty("policy").GetString()! : "";
                foreach (var cell in json.RootElement.EnumerateObject())
                {
                    var text = cell.Value.ToString();
                    var allowed = CaptureCell(table, cell.Name, row, text);
                    if (allowed && table != "oidc_rate_limit_buckets")
                    {
                        // A permission is exact in table, column, kind, record, and value;
                        // even the same value in a different column remains a violation.
                        Assert.True(IsSnapshotKindAllowed(table, cell.Name, text), "Invalid snapshot exception.");
                        seen.Add((table, cell.Name, row, text));
                    }
                }
            }
        }
        Assert.True(_snapshots.SetEquals(seen), "A required exact snapshot was not persisted.");
    }

    internal bool CaptureCell(string table, string column, string row, string text)
    {
        // PS-24 permits the exact HMAC digest in this column, never as a diagnostic.
        if (table == "oidc_rate_limit_buckets" && column == "partition_digest" &&
            SignaCore.Host.Security.OidcRateLimitPolicies.All.Contains(row) &&
            _canaries.Contains(("partition-digest", text))) return true;
        if (_snapshots.Contains((table, column, row, text)) && IsSnapshotKindAllowed(table, column, text)) return true;
        Capture("database:" + table + "." + column, text);
        return false;
    }

    private bool IsSnapshotKindAllowed(string table, string column, string value) => _canaries.Any(canary =>
        canary.Value == value && (table, column, canary.Kind) is
            ("authorization_requests", "state", "state") or
            ("authorization_requests", "nonce", "nonce") or
            ("authorization_requests", "code_challenge", "challenge") or
            ("authorization_codes", "nonce", "nonce") or
            ("authorization_codes", "code_challenge", "challenge") or
            ("logout_requests", "state", "state"));
}

/// <summary>All tag values are scanned; only these two hosts' framework meters are selected.</summary>
internal sealed class OidcSignalCapture : IDisposable
{
    private readonly MeterListener _meter = new();
    private readonly ActivityListener _activities;
    private readonly ConcurrentQueue<(string Meter, string Key, string Value)> _tags = new();
    private readonly ConcurrentQueue<string> _spans = new();
    private readonly HashSet<object> _scopes;

    public OidcSignalCapture(params TestHost[] hosts)
    {
        _scopes = hosts.Select(host => (object)host.Factory.Services.GetRequiredService<IMeterFactory>()).ToHashSet();
        _meter.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Scope is null || _scopes.Contains(instrument.Meter.Scope))
                listener.EnableMeasurementEvents(instrument);
        };
        _meter.SetMeasurementEventCallback<long>((instrument, _, tags, _) => Record(instrument, tags));
        _meter.SetMeasurementEventCallback<int>((instrument, _, tags, _) => Record(instrument, tags));
        _meter.SetMeasurementEventCallback<double>((instrument, _, tags, _) => Record(instrument, tags));
        _meter.Start();
        _activities = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            SampleUsingParentId = (ref ActivityCreationOptions<string> _) => ActivitySamplingResult.AllData,
            ActivityStopped = activity =>
            {
                foreach (var tag in activity.TagObjects) _spans.Enqueue(tag.Key + "=" + tag.Value);
                foreach (var item in activity.Events)
                    foreach (var tag in item.Tags) _spans.Enqueue(tag.Key + "=" + tag.Value);
            }
        };
        ActivitySource.AddActivityListener(_activities);
    }

    private void Record(Instrument instrument, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        foreach (var tag in tags)
            _tags.Enqueue((instrument.Meter.Name, tag.Key, Convert.ToString(tag.Value, CultureInfo.InvariantCulture) ?? ""));
    }

    public void VerifyAndCopy(OidcCanaryScan scan, params string[] clients)
    {
        _meter.RecordObservableInstruments();
        Assert.Contains(_tags, tag => tag.Meter == "SignaCore");
        Assert.NotEmpty(_spans);
        foreach (var tag in _tags)
        {
            scan.Capture("meter", tag.Key + "=" + tag.Value);
            Assert.False(tag.Key is "client.address" or "url.full" or "url.query" ||
                tag.Key.StartsWith("user.", StringComparison.Ordinal) || tag.Key.StartsWith("enduser.", StringComparison.Ordinal),
                "A metric used a forbidden tag key.");
            if (tag.Meter == "SignaCore")
            {
                Assert.True(new[] { "endpoint", "outcome", "reason", "grant_type", "source", "client_id" }.Contains(tag.Key), "A product metric used an unapproved tag key.");
                if (tag.Key == "client_id") Assert.True(clients.Contains(tag.Value), "Metric client was not registered.");
            }
            if (tag.Meter == "Microsoft.AspNetCore.RateLimiting")
            {
                Assert.True(new[] { "aspnetcore.rate_limiting.policy", "aspnetcore.rate_limiting.result" }.Contains(tag.Key), "A limiter metric used an unapproved tag key.");
                if (tag.Key.EndsWith("policy", StringComparison.Ordinal)) Assert.True(SignaCore.Host.Security.OidcRateLimitPolicies.All.Contains(tag.Value), "A limiter metric used an unapproved policy.");
                else Assert.True(new[] { "acquired", "endpoint_limiter", "global_limiter", "request_canceled" }.Contains(tag.Value), "A limiter metric used an unapproved result.");
            }
        }
        foreach (var span in _spans) scan.Capture("trace", span);
    }

    public void Dispose() { _activities.Dispose(); _meter.Dispose(); }
}
