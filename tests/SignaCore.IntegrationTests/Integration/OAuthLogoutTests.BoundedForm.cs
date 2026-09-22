using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Host.Security;
using ServiceMantle.AspNetCore.Health;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using Xunit;

namespace SignaCore.Tests.Integration;

public sealed partial class OAuthLogoutTests
{
    private const string GateFailure = "{\"error\":\"invalid_request\",\"error_description\":\"The form request is invalid.\"}";

    public static IEnumerable<object[]> LogoutBodyMatrix =>
        from credential in new[] { "basic", "post", "none" }
        from length in new[] { "known", "unknown", "understated" }
        from size in new[] { 16384, 16385 }
        select new object[] { credential, length, size };

    [Theory]
    [MemberData(nameof(LogoutBodyMatrix))]
    public async Task Prepare_RealByteBoundary_WithValidHintAndEveryCredentialCarrier(
        string credential, string length, int size)
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        await SeedLogoutAppAsync();
        var hint = await MintIdTokenAsync(accountId, sessionId);
        var prefix = "id_token_hint=" + hint;
        if (credential == "post") prefix += "&client_id=" + AppId + "&client_secret=" + AppSecret;
        // Empty segments add raw bytes without inventing an unknown field or invalid hint.
        var payload = Encoding.UTF8.GetBytes(prefix + new string('&', size - Encoding.UTF8.GetByteCount(prefix)));
        var stream = new CountingFormStream(payload);
        var beforeRows = await QueryAsync(db => db.LogoutRequests.CountAsync(TestContext.Current.CancellationToken));
        var beforeAudit = (await QueryAsync(db => SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, TestContext.Current.CancellationToken))).Count;
        var response = await host.Server.SendAsync(context =>
        {
            context.Request.Method = "POST";
            context.Request.Path = "/oauth2/logout/requests";
            context.Request.ContentType = "application/x-www-form-urlencoded";
            context.Request.ContentLength = length == "known" ? size : length == "understated" ? 1 : null;
            context.Request.Body = stream;
            if (credential == "basic") context.Request.Headers.Authorization = BasicHeader().ToString();
        }, TestContext.Current.CancellationToken);
        using var reader = new StreamReader(response.Response.Body);
        var body = await reader.ReadToEndAsync(TestContext.Current.CancellationToken);
        var success = size == 16384 && credential != "none";
        Assert.Equal(size == 16385 ? 400 : success ? 200 : 401, response.Response.StatusCode);
        Assert.Equal(size, stream.TotalRead);
        if (size == 16385) Assert.Equal(GateFailure, body);
        if (success) Assert.Contains("logout_uri", body, StringComparison.Ordinal);
        Assert.Equal(beforeRows + (success ? 1 : 0),
            await QueryAsync(db => db.LogoutRequests.CountAsync(TestContext.Current.CancellationToken)));
        Assert.Equal(beforeAudit + (success ? 1 : 0),
            (await QueryAsync(db => SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, TestContext.Current.CancellationToken))).Count);
        if (success)
        {
            var handle = System.Text.Json.JsonDocument.Parse(body).RootElement.GetProperty("logout_uri").GetString()!.Split('=')[1];
            var digest = LoginHandleDigest.Compute(handle);
            var request = await QueryAsync(db => db.LogoutRequests.AsNoTracking().SingleAsync(row => row.HandleDigest == digest, TestContext.Current.CancellationToken));
            var audit = Assert.Single(
                (await QueryAsync(db => SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, TestContext.Current.CancellationToken)))
                .Where(row => row.TargetId == request.Id.ToString("D") && row.Action == "oidc.logout.prepared"));
            Assert.Equal("logoutrequest", audit.TargetType);
        }
        Assert.False(body.Contains(hint, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("application/x-www-form-urlencoded")]
    [InlineData("application/x-www-form-urlencoded; charset=utf-8")]
    [InlineData("application/x-www-form-urlencoded; charset=\"UTF-8\"")]
    [InlineData("Application/X-WWW-Form-Urlencoded; Charset=UtF-8")]
    public async Task Prepare_AcceptsUtf8MediaVariants_WithOneValidHint(string contentType)
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        await SeedLogoutAppAsync();
        var hint = await MintIdTokenAsync(accountId, sessionId);
        using var http = host.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/logout/requests");
        request.Headers.Authorization = BasicHeader();
        request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes("id_token_hint=" + hint));
        request.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        using var response = await http.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("/oauth2/logout/requests", "oversize")]
    [InlineData("/OAuth2/Logout/Requests/", "oversize")]
    [InlineData("/mounted/oauth2/logout/requests", "oversize")]
    [InlineData("/oauth2/logout/requests", "percent")]
    [InlineData("/oauth2/logout/requests", "utf8")]
    [InlineData("/oauth2/logout/requests", "charset")]
    [InlineData("/oauth2/logout/requests", "json")]
    [InlineData("/oauth2/logout/requests", "text")]
    [InlineData("/oauth2/logout/requests", "multipart")]
    [InlineData("/oauth2/logout/requests", "encoding")]
    [InlineData("/oauth2/logout/requests", "io")]
    [InlineData("/oauth2/logout/requests", "internal-cancel")]
    public async Task Prepare_RejectedOuterInput_NeverLooksUpClientOrWritesAnything(string path, string mode)
    {
        var repository = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);
        repository.Setup(repo => repo.DeactivateExpiredCallbacksAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);
        using var host = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<IAppRegistrationRepository>();
            services.AddSingleton(repository.Object);
        });
        using var http = host.CreateClient();
        var beforeRows = await QueryAsync(db => db.LogoutRequests.CountAsync(TestContext.Current.CancellationToken));
        var beforeAudit = (await QueryAsync(db => SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, TestContext.Current.CancellationToken))).Count;
        var payload = mode switch
        {
            "oversize" => Encoding.ASCII.GetBytes("id_token_hint=" + new string('a', 20000)),
            "percent" => Encoding.ASCII.GetBytes("id_token_hint=%G1"),
            "utf8" => Encoding.ASCII.GetBytes("id_token_hint=%FF"),
            _ => Encoding.ASCII.GetBytes("id_token_hint=synthetic-canary-hint")
        };
        var stream = new CountingFormStream(payload, mode is "io" or "internal-cancel" ? mode : null);
        var response = await host.Server.SendAsync(context =>
        {
            context.Request.Method = "POST";
            context.Request.Path = path;
            if (path.StartsWith("/mounted", StringComparison.Ordinal))
            {
                context.Request.PathBase = "/mounted";
                context.Request.Path = path["/mounted".Length..];
            }
            context.Request.QueryString = new QueryString("?client_id=" + AppId);
            context.Request.Headers.Authorization = BasicHeader().ToString();
            context.Request.Headers["X-Correlation-Id"] = "logout-gate-probe";
            context.Request.ContentType = mode switch
            {
                "charset" => "application/x-www-form-urlencoded; charset=iso-8859-1",
                "json" => "application/json",
                "text" => "text/plain",
                "multipart" => "multipart/form-data; boundary=probe",
                _ => "application/x-www-form-urlencoded"
            };
            if (mode == "encoding") context.Request.Headers.ContentEncoding = "gzip";
            context.Request.Body = stream;
        }, TestContext.Current.CancellationToken);
        using var reader = new StreamReader(response.Response.Body);
        var body = await reader.ReadToEndAsync(TestContext.Current.CancellationToken);
        Assert.Equal(mode is "io" or "internal-cancel" ? 503 : 400, response.Response.StatusCode);
        Assert.Equal(mode is "io" or "internal-cancel"
            ? "{\"error\":\"server_error\",\"error_description\":\"The request could not be processed.\"}" : GateFailure, body);
        Assert.InRange(stream.TotalRead, 0, 16385);
        if (mode == "oversize") Assert.Equal(16385, stream.TotalRead);
        if (mode is "charset" or "json" or "text" or "multipart" or "encoding") Assert.Equal(0, stream.TotalRead);
        Assert.Equal("no-store", response.Response.Headers.CacheControl.ToString());
        Assert.Equal("no-cache", response.Response.Headers.Pragma.ToString());
        Assert.Equal("logout-gate-probe", response.Response.Headers["X-Correlation-Id"].ToString());
        Assert.Empty(response.Response.Headers.Location.ToString());
        repository.Verify(repo => repo.DeactivateExpiredCallbacksAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.AtMost(int.MaxValue));
        repository.VerifyNoOtherCalls();
        Assert.Equal(beforeRows, await QueryAsync(db => db.LogoutRequests.CountAsync(TestContext.Current.CancellationToken)));
        Assert.Equal(beforeAudit, (await QueryAsync(db => SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, TestContext.Current.CancellationToken))).Count);
    }

    [Fact]
    public async Task Prepare_MalformedInput_ConsumesSourceBudgetBeforeItsMarkerAnswer()
    {
        using var host = CreateLogoutHost();
        using var http = host.CreateClient();
        for (var i = 0; i <= IdentityConstants.OidcLogoutRateLimitPerMinute; i++)
        {
            using var content = new StringContent("id_token_hint=%FF", Encoding.UTF8, "application/x-www-form-urlencoded");
            using var response = await http.PostAsync("/oauth2/logout/requests", content, TestContext.Current.CancellationToken);
            Assert.Equal(i == IdentityConstants.OidcLogoutRateLimitPerMinute
                ? HttpStatusCode.TooManyRequests : HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [Fact]
    public async Task Prepare_PhaseRejection_PrecedesTheMalformedMarker()
    {
        var source = new Mock<IServiceHealthSnapshotSource>();
        source.Setup(value => value.GetSnapshotAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ServiceHealthSnapshot(ServiceStartupPhase.PendingSetup,
                ServiceMigrationReadinessState.Succeeded, ServiceDatabaseReadinessState.Reachable));
        using var host = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<IServiceHealthSnapshotSource>();
            services.AddSingleton(source.Object);
        });
        using var http = host.CreateClient();
        using var response = await http.PostAsync("/oauth2/logout/requests",
            new StringContent("id_token_hint=%FF", Encoding.UTF8, "application/x-www-form-urlencoded"),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("service.phase.unavailable",
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Prepare_ConcurrentValidForms_KeepTheirOwnState()
    {
        using var host = CreateLogoutHost();
        var (account, session, _) = await LoginAndCaptureSessionAsync(host);
        await SeedLogoutAppAsync();
        var hint = await MintIdTokenAsync(account, session);
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader();
        var states = new[] { "first-state-0123456789012345", "second-state-012345678901234" };
        var sends = states.Select(state => http.PostAsync("/oauth2/logout/requests",
            new StringContent("id_token_hint=" + hint + "&state=" + state, Encoding.UTF8, "application/x-www-form-urlencoded"),
            TestContext.Current.CancellationToken));
        var responses = await Task.WhenAll(sends);
        foreach (var response in responses)
        {
            using (response) Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        var saved = await QueryAsync(db => db.LogoutRequests.Where(row => row.IdentitySessionId == session)
            .Select(row => row.State).ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(states.Order(), saved.Order());
    }

    private sealed class CountingFormStream(byte[] payload, string? failure = null) : Stream
    {
        public int TotalRead { get; private set; }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (TotalRead > 0 && failure is not null)
            {
                if (failure == "io") throw new IOException("Synthetic read failure.");
                throw new OperationCanceledException();
            }
            var count = Math.Min(7, Math.Min(buffer.Length, payload.Length - TotalRead));
            payload.AsSpan(TotalRead, count).CopyTo(buffer.Span);
            TotalRead += count;
            return ValueTask.FromResult(count);
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
