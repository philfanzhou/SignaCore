using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using ServiceMantle.AspNetCore.Logging;
using ServiceMantle.Logging;
using ServiceMantle.Serilog;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Host.Configuration;
using SignaCore.Host.Security;
using SignaCore.Host.Telemetry;
using Xunit;
using static SignaCore.Tests.Integration.OidcDatabaseTestSupport;
using static SignaCore.Tests.Integration.ServiceMantleLoggingTests;

namespace SignaCore.Tests.Integration;

[Collection(HostConsoleCaptureCollection.Name)]
public sealed partial class OidcSensitiveCanaryMatrixDatabaseContractTests
{
    [Fact]
    public async Task RealTwoHostFlows_KeepCanariesOutOfEveryNonContractCarrier()
    {
        var scan = new OidcCanaryScan();
        scan.Add("secret", ClientSecret);
        scan.Add("authorization", BasicHeader(ClientId, ClientSecret).ToString());
        scan.Add("verifier", CodeVerifier);
        scan.Add("challenge", CodeChallenge);
        scan.Add("partition", "ip:" + RemoteIp);
        scan.Add("partition", "client:" + ClientId);
        await using var loki = await FakeLoki.StartAsync();
        using var console = new ConsoleCapture();
        await using var harness = await Harness.CreateAsync(new Dictionary<string, string>
        {
            [SystemSettingKeys.LokiUri] = loki.HttpsAddress,
            [SystemSettingKeys.LokiAuthorization] = "Bearer " + Guid.NewGuid().ToString("N")
        });
        await EnableFlowsAsync(harness);
        void Configure(IServiceCollection services)
        {
            var options = RegisteredLokiOptions(services);
            options.Endpoint = new Uri(loki.HttpAddress);
            options.AllowInsecureLoopbackForTesting = true;
        }
        var a = harness.CreateHost(Configure, captureLogs: false);
        var b = harness.CreateHost(Configure, captureLogs: false);
        var marker = "matrix-probe-" + Guid.NewGuid().ToString("N");
        try
        {
            AssertArchitecture(a);
            AssertArchitecture(b);
            using var signals = new OidcSignalCapture(a, b);
            WriteCanaryProbe(a, scan, marker);
            WriteCanaryProbe(b, scan, marker);
            CaptureHeaderProjection(a, scan, scan.New("header"));
            CaptureHeaderProjection(b, scan, scan.New("header"));

            // C1/C2/C3: genuine login, cross-host authorize, redemption and code replay.
            var codeFlow = await LoginAndAuthorizeAsync(harness, a, b, scan, exerciseFailures: true);
            var tokens = await ExchangeAsync(a, scan, codeFlow.Code);
            using (var replay = await a.Client.SendAsync(OidcAttackRateLimitDatabaseContractTests.Redeem(codeFlow.Code), Ct))
                await CaptureAsync(scan, replay, HttpStatusCode.BadRequest);
            var wrongVerifier = await LoginAndAuthorizeAsync(harness, a, b, scan);
            using (var wrong = await a.Client.SendAsync(OidcAttackRateLimitDatabaseContractTests.Redeem(wrongVerifier.Code, scan.New("wrong_verifier")), Ct))
                await CaptureAsync(scan, wrong, HttpStatusCode.BadRequest);

            // C4 gets a new session/family: code replay above revoked the earlier state.
            var refreshFlow = await LoginAndAuthorizeAsync(harness, a, b, scan);
            var refreshTokens = await ExchangeAsync(a, scan, refreshFlow.Code);
            using (var rotation = await b.Client.SendAsync(Form("/oauth2/token", ("grant_type", "refresh_token"), ("refresh_token", refreshTokens.Refresh)), Ct))
                await TokensAsync(scan, rotation);
            using (var reuse = await b.Client.SendAsync(Form("/oauth2/token", ("grant_type", "refresh_token"), ("refresh_token", refreshTokens.Refresh)), Ct))
                await CaptureAsync(scan, reuse, HttpStatusCode.BadRequest);

            // C5/C6: valid UserInfo, then logout preparation on B and completion on A.
            var logoutFlow = await LoginAndAuthorizeAsync(harness, a, b, scan);
            var logoutTokens = await ExchangeAsync(a, scan, logoutFlow.Code);
            using (var profile = await a.Client.SendAsync(UserInfo(logoutTokens.Access), Ct))
                await CaptureAsync(scan, profile, HttpStatusCode.OK);
            using (var invalid = await a.Client.SendAsync(UserInfo(scan.New("bearer")), Ct))
                await CaptureAsync(scan, invalid, HttpStatusCode.Unauthorized);
            var state = scan.New("state");
            string logoutUri;
            using (var preparation = await b.Client.SendAsync(Form("/oauth2/logout/requests",
                       ("id_token_hint", logoutTokens.Id), ("post_logout_redirect_uri", PostLogout), ("state", state)), Ct))
            {
                Assert.Equal(HttpStatusCode.OK, preparation.StatusCode);
                var body = JsonDocument.Parse(await preparation.Content.ReadAsStringAsync(Ct));
                logoutUri = body.RootElement.GetProperty("logout_uri").GetString()!;
                var handle = QueryValue(logoutUri, "logout_handle");
                scan.Add("handle", handle);
                // Only the handle field within the logout URI is contracted.
                await CaptureAsync(scan, preparation, HttpStatusCode.OK, json: new Dictionary<string, string>
                    { ["logout_uri"] = logoutUri });
                scan.Capture("http", RemoveQueryValues(logoutUri, new Dictionary<string, string> { ["logout_handle"] = handle }));
                await using var db = harness.Context();
                var row = await db.LogoutRequests.SingleAsync(Ct);
                scan.AllowSnapshot("logout_requests", "state", row.Id, state);
            }
            using (var completion = await a.Client.SendAsync(Get(logoutUri, logoutFlow.Cookie), Ct))
                await CaptureAsync(scan, completion, HttpStatusCode.Found, query: new Dictionary<string, string> { ["state"] = state }, cookies: true);
            using (var replay = await a.Client.SendAsync(Get(logoutUri, logoutFlow.Cookie), Ct))
                await CaptureAsync(scan, replay, HttpStatusCode.BadRequest);

            // C7 uses its own still-live family, then an invalid opaque token.
            var revokeFlow = await LoginAndAuthorizeAsync(harness, a, b, scan);
            var revokeTokens = await ExchangeAsync(a, scan, revokeFlow.Code);
            var revokedDigest = RefreshTokenDigest.Compute(revokeTokens.Refresh);
            await using (var db = harness.Context())
                Assert.False((await db.RefreshTokens.SingleAsync(row => row.TokenValue == revokedDigest, Ct)).IsRevoked);
            using (var valid = await b.Client.SendAsync(Form("/oauth2/revoke", ("token", revokeTokens.Refresh)), Ct))
                await CaptureAsync(scan, valid, HttpStatusCode.OK);
            using (var invalid = await b.Client.SendAsync(Form("/oauth2/revoke", ("token", scan.New("refresh"))), Ct))
                await CaptureAsync(scan, invalid, HttpStatusCode.OK);
            await using (var db = harness.Context())
                Assert.True((await db.RefreshTokens.SingleAsync(row => row.TokenValue == revokedDigest, Ct)).IsRevoked);

            // C8: rejection, an actual PostgreSQL lock timeout, and rollback on audit failure.
            await harness.ExecuteAsync("UPDATE oidc_rate_limit_buckets SET permit_count = 90, window_expires_at = now() + interval '1 hour' WHERE policy = 'oidc-token'");
            using (var busy = await a.Client.SendAsync(OidcAttackRateLimitDatabaseContractTests.Redeem(wrongVerifier.Code), Ct))
                await CaptureAsync(scan, busy, HttpStatusCode.TooManyRequests);
            var digest = a.Digest("client:" + ClientId);
            scan.Add("partition-digest", digest);
            await using (await harness.LockRowAsync(OidcRateLimitPolicies.Token, digest))
            using (var unavailable = await b.Client.SendAsync(OidcAttackRateLimitDatabaseContractTests.Redeem(wrongVerifier.Code), Ct))
                await CaptureAsync(scan, unavailable, HttpStatusCode.ServiceUnavailable);
            // Reset the measured budgets before preparing the independent rollback case.
            await harness.ExecuteAsync("DELETE FROM oidc_rate_limit_buckets");
            using (var fault = harness.CreateHost(services =>
                   {
                       Configure(services);
                       services.Replace(ServiceDescriptor.Singleton<IAuditService>(new OidcSensitiveValueMatrixTests.ThrowingAuditService(exception => scan.Capture("exception", exception.ToString()), failLogin: true)));
                   }, captureLogs: false))
                await AuditRollbackAsync(harness, a, fault, scan);

            foreach (var host in new[] { a, b })
            {
                using var scrape = new HttpRequestMessage(HttpMethod.Get, "/metrics");
                scrape.Headers.Add("X-Admin-AppId", ClientId);
                scrape.Headers.Add("X-Admin-AppSecret", ClientSecret);
                using var response = await host.Client.SendAsync(scrape, Ct);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                var text = await response.Content.ReadAsStringAsync(Ct);
                Assert.True(text.Split('\n').Any(line => line.StartsWith("oidc_", StringComparison.Ordinal)), "No OIDC series was exported.");
                scan.Capture("prometheus", text);
            }
            signals.VerifyAndCopy(scan, ClientId);
            await using (var db = harness.Context())
            {
                var audits = await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, Ct);
                foreach (var action in new[] { "oidc.authorize.validated", "oidc.code.redeemed", "oidc.code.replayed",
                             "oidc.refresh.replayed", "oidc.logout.prepared", "oidc.logout.completed" })
                    Assert.True(audits.Any(row => row.Action == action), "Missing expected audit event: " + action);
                foreach (var outcome in new[] { "login_success", "login_failure" })
                    Assert.True(await db.LoginHistories.AnyAsync(row => row.AuthMethod == "oidc_login" && row.EventType == outcome, Ct),
                        "Missing expected login history: " + outcome);
            }
            await scan.ScanDatabaseAsync(harness);
        }
        finally
        {
            // Dispose before observing Console/Loki: shared shutdown drains the final batch.
            a.Dispose();
            b.Dispose();
        }
        Assert.True(console.Output.Contains(marker, StringComparison.Ordinal), "Console probe missing.");
        Assert.True(loki.Bodies.Any(body => body.Contains(marker, StringComparison.Ordinal)), "Loki probe missing.");
        scan.Capture("console", console.Output);
        foreach (var batch in loki.Bodies) scan.Capture("loki", batch);
        scan.AssertClean();
    }

    private static void WriteCanaryProbe(TestHost host, OidcCanaryScan scan, string marker)
    {
        // Deliberately exercise sensitive field names with an independent, non-credential
        // marker. Never send a value from an authentication flow into a logging probe.
        var probe = "logging-probe-" + Guid.NewGuid().ToString("N");
        scan.Add("logging-probe", probe);
        WriteProbe(host.Factory.Services, marker, probe);
    }

    [Fact]
    public async Task NegativeWiringVariants_DetectArchitectureRawLoggingAndMissingHeaderRegistration()
    {
        using var console = new ConsoleCapture();
        await using var harness = await Harness.CreateAsync();
        using (var wrapper = harness.CreateHost(services =>
               {
                   var type = typeof(SerilogOptions).Assembly.GetType("ServiceMantle.Serilog.RuntimeLoggerProvider", true)!;
                   services.RemoveAll<ILoggerProvider>();
                   services.AddSingleton<ILoggerProvider>(provider => new TransparentLoggerProvider((ILoggerProvider)ActivatorUtilities.CreateInstance(provider, type)));
               }, captureLogs: false))
            Assert.NotNull(Record.Exception(() => Assert.Empty(LoggingPipelineViolations(wrapper.Factory.Services))));

        // The raw factory lives only in this variant. It never forwards canaries to Console/Loki.
        using (var raw = harness.CreateHost())
        {
            var scan = new OidcCanaryScan();
            WriteCanaryProbe(raw, scan, "raw-probe");
            foreach (var line in raw.Probe.Logs) scan.Capture("raw-log", line);
            Assert.NotNull(Record.Exception(scan.AssertClean));
        }
        using (var missingHeader = harness.CreateHost(services =>
               {
                   var options = Assert.Single(services.Where(item => item.ServiceType.Name == "SensitiveHeaderRegistration")
                       .Select(item => item.ImplementationInstance!)
                       .Select(item => (SensitiveHeadersOptions)item.GetType().GetProperty("Options")!.GetValue(item)!),
                       item => item.DeniedHeaderNames.Contains("X-Admin-AppSecret"));
                   options.DeniedHeaderNames = [];
               }, captureLogs: false))
        {
            var scan = new OidcCanaryScan();
            Assert.NotNull(Record.Exception(() => Assert.True(missingHeader.Factory.Services.GetRequiredService<SensitiveHeaderRegistry>().IsSensitive("X-Admin-AppSecret"))));
            CaptureHeaderProjection(missingHeader, scan, scan.New("header"));
            Assert.NotNull(Record.Exception(scan.AssertClean));
        }
    }

    [Theory]
    [InlineData("console")]
    [InlineData("loki")]
    [InlineData("http")]
    [InlineData("database:service_audit_logs.description")]
    [InlineData("meter")]
    [InlineData("trace")]
    [InlineData("prometheus")]
    [InlineData("exception")]
    [InlineData("failure-message")]
    [InlineData("header-projection")]
    public void EveryCarrier_DetectsPlantedValuesWithoutPrintingThem(string carrier)
    {
        var scan = new OidcCanaryScan();
        var canary = scan.New("state");
        scan.Capture(carrier, canary);
        var failure = Record.Exception(scan.AssertClean);
        Assert.NotNull(failure);
        Assert.False(failure.ToString().Contains(canary, StringComparison.Ordinal), "The failure report disclosed a canary.");
        Assert.Equal(new[] { "canary #0: " + carrier }, scan.Violations());
    }

    [Fact]
    public void SnapshotException_IsExactInKindColumnRecordAndValue()
    {
        var scan = new OidcCanaryScan();
        var state = scan.New("state");
        var row = Guid.NewGuid();
        scan.AllowSnapshot("authorization_requests", "state", row, state);
        Assert.True(scan.CaptureCell("authorization_requests", "state", row.ToString(), state));
        scan.AssertClean();
        Assert.False(scan.CaptureCell("authorization_requests", "nonce", row.ToString(), state));
        Assert.False(scan.CaptureCell("authorization_requests", "state", Guid.NewGuid().ToString(), state));
        Assert.False(scan.CaptureCell("service_audit_logs", "description", row.ToString(), state));
        Assert.NotNull(Record.Exception(scan.AssertClean));
        var password = scan.New("password");
        scan.AllowSnapshot("authorization_requests", "state", row, password);
        Assert.False(scan.CaptureCell("authorization_requests", "state", row.ToString(), password));
        var digest = scan.Add("partition-digest", Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N"));
        Assert.True(scan.CaptureCell("oidc_rate_limit_buckets", "partition_digest", "oidc-token", digest));
        Assert.False(scan.CaptureCell("oidc_rate_limit_buckets", "policy", "oidc-token", digest));
        Assert.False(scan.CaptureCell("service_audit_logs", "description", row.ToString(), digest));
    }

    private static void CaptureHeaderProjection(TestHost host, OidcCanaryScan scan, string value) =>
        scan.Capture("header-projection", JsonSerializer.Serialize(host.Factory.Services
            .GetRequiredService<RequestHeaderDiagnosticProjector>().Project(new HeaderDictionary { ["X-Admin-AppSecret"] = value })));

    private static void AssertArchitecture(TestHost host)
    {
        var services = host.Factory.Services;
        Assert.Empty(LoggingPipelineViolations(services));
        Assert.True(services.GetRequiredService<SensitiveHeaderRegistry>().IsSensitive("X-Admin-AppSecret"));
        Assert.Contains(services.GetServices<SignaCoreTelemetry.MeterSelection>(), selection => selection.MeterNames.Contains("SignaCore"));
        var endpoint = Assert.Single(services.GetServices<EndpointDataSource>().SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>(), endpoint => endpoint.RoutePattern.RawText == "/metrics");
        Assert.Contains(endpoint.Metadata, item => item.GetType().FullName == "ServiceMantle.OpenTelemetry.Prometheus.PrometheusEndpointMetadata");
        var factory = services.GetRequiredService<ILoggerFactory>();
        Assert.False(factory.CreateLogger("Microsoft.AspNetCore.Hosting.Diagnostics").IsEnabled(LogLevel.Information));
        Assert.False(factory.CreateLogger("Microsoft.EntityFrameworkCore.Database.Command").IsEnabled(LogLevel.Information));
        using var shipped = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepositoryRoot(), "src/SignaCore.Host/appsettings.json")));
        foreach (var category in new[] { "Microsoft.AspNetCore", "Microsoft.EntityFrameworkCore" })
            Assert.True(Enum.Parse<LogLevel>(shipped.RootElement.GetProperty("Logging").GetProperty("LogLevel").GetProperty(category).GetString()!) >= LogLevel.Warning);
        // Complements #396/#397's reference checks with actual locally-defined types, including
        // subclasses of BaseExporter<T> and implementations of sink/provider contracts.
        foreach (var assembly in new[] { typeof(Program).Assembly, typeof(IAuditService).Assembly, typeof(AppRegistrationEntity).Assembly })
        foreach (var type in assembly.GetTypes())
        {
            Assert.False(type.GetInterfaces().Any(contract => typeof(ILoggerProvider) == contract ||
                contract.Assembly.GetName().Name!.StartsWith("Serilog", StringComparison.Ordinal)), "A product assembly owns logging infrastructure.");
            for (var parent = type.BaseType; parent is not null; parent = parent.BaseType)
                Assert.False(parent.FullName?.StartsWith("OpenTelemetry.BaseExporter", StringComparison.Ordinal) == true, "A product assembly owns an exporter.");
        }
    }
}
