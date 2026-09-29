using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services.Sms;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginSmsCodeTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The sensitive-value scan of the browser SMS send route (#444) and the SMS login (#445,
/// <c>DF-16</c>, <c>DF-17</c>): with canary phones, a canary <c>otp</c> field, and the code the
/// provider stand-in receives, every path — sent, suppressed, provider-rejected, invalid phone,
/// local 400, an ineligible and a wrong-code SMS login, and a successful one — runs under the
/// default log levels, and no raw phone, code, handle, request token, or antiforgery cookie reaches
/// a log line, a metric label, a span tag or name, a response body or header, or any database
/// column other than the two the contract names for the normalized phone
/// (<c>user_logins.provider_user_id</c>, <c>otps.phone</c>). The only place a response carries a
/// phone is the normalized value of the page's own phone input. The audit rows hold only the
/// masked phone, and the plaintext code exists only in the provider request and the one form body
/// that submits it.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed partial class OAuthLoginSmsCodeSensitiveValueScanTests : IClassFixture<IdentityServerFixture>
{
    private const string CanaryOtp = "987654";

    private readonly IdentityServerFixture _fixture;

    public OAuthLoginSmsCodeSensitiveValueScanTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task PhonesAndCodesNeverReachLogsMetricsTracesBodiesOrOtherColumns()
    {
        var sender = new FakeSmsSender();
        var capture = new ConcurrentQueue<string>();
        using var metrics = new SmsCodeMetricsCollector();
        var spans = new ConcurrentQueue<string>();
        using var activities = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                spans.Enqueue(activity.DisplayName + " " + activity.OperationName);
                foreach (var tag in activity.TagObjects)
                {
                    spans.Enqueue(tag.Key + "=" + tag.Value);
                }
            }
        };
        ActivitySource.AddActivityListener(activities);
        using var host = _fixture.CreateSmsHost(sender, services =>
        {
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
            {
                logging.AddProvider(new CapturingLoggerProvider(capture));
                logging.SetMinimumLevel(LogLevel.Information);
                logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
                logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
            }));
        });
        using var client = host.CreateBrowserClient();
        var app = await SeedSmsAppAsync(host.Services, SmsLoginMode.ManualApproval);
        var session = await BeginAsync(host.Services, client, app);
        var admitted = NewPhone();
        var unregistered = NewPhone();
        var rejected = NewPhone();
        var overLong = NewPhone();
        var invalid = NewPhone()[..9];
        await SeedIdentityAsync(host.Services, E164(admitted), admission: (app.Id, SmsAccessApprovalSource.Admin, true));
        await SeedIdentityAsync(host.Services, E164(rejected), admission: (app.Id, SmsAccessApprovalSource.Admin, true));

        var bodies = new List<string>();
        async Task SendAsync(string phone, HttpStatusCode expected, Action? before = null)
        {
            before?.Invoke();
            using var response = await client.SendAsync(
                SendPost(session, fields: [.. SendFields(session, phone), new("otp", CanaryOtp)]),
                TestContext.Current.CancellationToken);
            Assert.Equal(expected, response.StatusCode);
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            bodies.Add(string.Join('\n', response.Headers.Concat(response.Content.Headers)
                .Select(header => header.Key + ": " + string.Join(',', header.Value))));
        }

        await SendAsync(admitted, HttpStatusCode.OK);
        await SendAsync("+86 " + admitted, HttpStatusCode.OK);
        await SendAsync(unregistered, HttpStatusCode.OK);
        await SendAsync(rejected, HttpStatusCode.OK, () =>
            sender.Behavior = (_, _) => throw new SmsDeliveryRejectedException("Rejected", "provider-" + rejected));
        await SendAsync(invalid, HttpStatusCode.OK);
        await SendAsync(new string(' ', 22) + overLong, HttpStatusCode.BadRequest);

        var codes = sender.Calls.Select(call => call.Code).ToList();
        Assert.Equal(2, codes.Count);

        // The SMS login: an ineligible phone, a wrong code, an invalid phone, and — last, because
        // it consumes the continuation — the delivered code.
        async Task LoginAsync(string phone, string otp, HttpStatusCode expected)
        {
            using var response = await client.SendAsync(
                OAuthLoginTestSupport.CreateLoginPost(
                    fields: [.. SendFields(session, phone), new("otp", otp), new("action", "sms_login")],
                    cookieHeader: CookieHeader(session),
                    correlationId: FixedCorrelationId),
                TestContext.Current.CancellationToken);
            Assert.Equal(expected, response.StatusCode);
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            bodies.Add(string.Join('\n', response.Headers.Concat(response.Content.Headers)
                .Select(header => header.Key + ": " + string.Join(',', header.Value))));
        }

        await LoginAsync(unregistered, CanaryOtp, HttpStatusCode.OK);
        await LoginAsync(admitted, CanaryOtp, HttpStatusCode.OK);
        await LoginAsync(invalid, CanaryOtp, HttpStatusCode.OK);
        await LoginAsync(admitted, codes[0], HttpStatusCode.Found);
        var rawValues = new List<string> { CanaryOtp, session.Handle, session.Token, session.CookieValue };
        rawValues.AddRange(codes);
        foreach (var phone in new[] { admitted, unregistered, rejected, overLong })
        {
            rawValues.Add(phone);
            rawValues.Add(E164(phone));
        }

        rawValues.Add(invalid);

        // Logs: proven non-empty through the fixed correlation id of the route's own log lines.
        var logText = string.Join('\n', capture);
        Assert.Contains(FixedCorrelationId, logText, StringComparison.Ordinal);
        Assert.Contains("Outcome=not_registered", logText, StringComparison.Ordinal);
        AssertAbsent("log", logText, rawValues);

        // Metrics and traces.
        Assert.NotEmpty(metrics.Outcomes);
        AssertAbsent("metric", string.Join('\n', metrics.TagValues), rawValues);
        AssertAbsent("trace", string.Join('\n', spans), rawValues);

        // Responses: no code; the handle and request token only in the page's own hidden fields,
        // which carry no new value; a phone only as the normalized value of the page's own phone
        // input, which is removed before the scan.
        var responses = PhoneInputValuePattern().Replace(string.Join('\n', bodies), "value=\"\"");
        Assert.Contains(PhoneInput(string.Empty), responses, StringComparison.Ordinal);
        AssertAbsent("response", responses, [.. rawValues.Except([session.Handle, session.Token])]);

        // Database: every column of every table, except the two phone columns the contract names.
        var dump = await DumpAllColumnsAsync(host.Services);
        Assert.Contains(E164(admitted)[..3] + "****" + E164(admitted)[^4..], dump, StringComparison.Ordinal);
        Assert.Contains("sms_code_suppressed", dump, StringComparison.Ordinal);
        Assert.Contains("otp_rejected", dump, StringComparison.Ordinal);
        Assert.Contains("login_success", dump, StringComparison.Ordinal);
        AssertAbsent("database", dump, rawValues);
        Assert.Contains(sender.Calls, call => call.PhoneE164 == E164(admitted));
    }

    [System.Text.RegularExpressions.GeneratedRegex("value=\"\\+861[3-9][0-9]{9}\"")]
    private static partial System.Text.RegularExpressions.Regex PhoneInputValuePattern();

    private static void AssertAbsent(string carrier, string text, IEnumerable<string> values)
    {
        var index = 0;
        foreach (var value in values)
        {
            // The failure names the carrier and the canary position only, never the value.
            Assert.False(text.Contains(value, StringComparison.Ordinal), $"Canary #{index} reached the {carrier}.");
            index++;
        }
    }

    private static async Task<string> DumpAllColumnsAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var connection = db.Database.GetDbConnection();
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var tables = new List<string>();
        await using (var list = connection.CreateCommand())
        {
            list.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'";
            await using var reader = await list.ExecuteReaderAsync(TestContext.Current.CancellationToken);
            while (await reader.ReadAsync(TestContext.Current.CancellationToken)) tables.Add(reader.GetString(0));
        }

        var dump = new StringBuilder();
        foreach (var table in tables)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM \"{table.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
            await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
            while (await reader.ReadAsync(TestContext.Current.CancellationToken))
            {
                for (var column = 0; column < reader.FieldCount; column++)
                {
                    var name = reader.GetName(column);
                    if ((table == "user_logins" && name == "provider_user_id") || (table == "otps" && name == "phone"))
                    {
                        continue;
                    }

                    dump.Append(table).Append('.').Append(name).Append('=')
                        .Append(reader.IsDBNull(column) ? string.Empty : Convert.ToString(reader.GetValue(column), System.Globalization.CultureInfo.InvariantCulture))
                        .Append('\n');
                }
            }
        }

        return dump.ToString();
    }

    private sealed class CapturingLoggerProvider(ConcurrentQueue<string> messages) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(string categoryName, ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                messages.Enqueue(exception is null
                    ? $"[{logLevel}] {categoryName}: {formatter(state, exception)}"
                    : $"[{logLevel}] {categoryName}: {formatter(state, exception)}\n{exception}");
            }
        }
    }
}
