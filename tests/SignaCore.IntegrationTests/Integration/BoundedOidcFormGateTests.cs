using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Security;
using SignaCore.Host.Startup;
using Xunit;
using SignaCoreDatabase = SignaCore.Database;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The outer bounded form read of <c>POST /oauth2/token</c> and <c>POST /oauth2/revoke</c>: one
/// read of at most 16385 raw bytes ahead of every later stage, one strict UTF-8 single-percent
/// decode, the fixed 400/503 answers after the shared phase and budget admit the request, and no
/// credential, client row, or grant side effect for a rejected body. Unit-level probes drive the
/// middleware directly over counting streams; the HTTP matrix runs over the real host; one smoke
/// drives a real Kestrel socket with chunked bodies (no Content-Length) — not only TestServer.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class BoundedOidcFormGateTests : IClassFixture<IdentityServerFixture>
{
    private const string FixedInvalidRequestBody =
        """{"error":"invalid_request","error_description":"The form request is invalid."}""";

    private readonly IdentityServerFixture _fixture;

    public BoundedOidcFormGateTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- The legal bound reaches grant dispatch ----

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    public async Task ALegalBodyAtExactly16384Bytes_ReachesTheOriginalDispatch(string path)
    {
        using var http = CreateClientWithBasicAuth();

        using var response = await http.PostAsync(
            path,
            RawForm(ExactBody(path)),
            TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        // The gate parsed and passed the form through: dispatch — not the fixed gate body.
        Assert.NotEqual(FixedInvalidRequestBody, body);
        if (path == "/oauth2/token")
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("unsupported_grant_type", body, StringComparison.Ordinal);
        }
        else
        {
            // Revoke with a well-formed synthetic token: the original always-200 contract.
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    // ---- Beyond the bound: the fixed 400 across every credential path ----

    [Theory]
    [InlineData(16385, "/oauth2/token", "basic")]
    [InlineData(16385, "/oauth2/revoke", "basic")]
    [InlineData(20 * 1024, "/oauth2/token", "basic")]
    [InlineData(20 * 1024, "/oauth2/revoke", "basic")]
    [InlineData(16385, "/oauth2/token", "post")]
    [InlineData(16385, "/oauth2/revoke", "post")]
    [InlineData(16385, "/oauth2/token", "none")]
    [InlineData(16385, "/oauth2/revoke", "none")]
    public async Task ABeyondTheBound_IsTheFixed400_OnEveryCredentialPath(
        int size, string path, string credentialPath)
    {
        using var http = credentialPath == "basic"
            ? CreateClientWithBasicAuth()
            : _fixture.CreateHttpClient();
        var content = RawForm(OversizedBody(size, includePostCredentials: credentialPath == "post"));

        using var response = await http.PostAsync(path, content, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(FixedInvalidRequestBody, body);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains("no-cache", string.Join(",", response.Headers.Pragma), StringComparison.Ordinal);
        Assert.False(response.Headers.Contains("Location"));
    }

    [Fact]
    public async Task ABodyWithNoContentLength_CannotSmugglePastTheBound()
    {
        using var http = CreateClientWithBasicAuth();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            // StreamContent without a known length is sent chunked: a lying or absent
            // Content-Length cannot smuggle a larger body past the byte-count bound.
            Content = new StreamContent(new ChunkedMemoryStream(OversizedBody(20 * 1024), 1024))
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

        using var response = await http.SendAsync(request, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(FixedInvalidRequestBody, body);
    }

    [Fact]
    public async Task AnOversizedBody_LeaksNoCanary()
    {
        var canary = "synthetic-canary-7c31e9d0b4a2";
        using var http = CreateClientWithBasicAuth();
        var payload = Encoding.ASCII.GetBytes(
            "grant_type=password&username=" + canary + "&password=" + canary + "&padding=" + new string('a', 20_000));

        using var response = await http.PostAsync(
            "/oauth2/token", RawForm(payload), TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(FixedInvalidRequestBody, body);
        Assert.DoesNotContain(canary, body, StringComparison.Ordinal);
    }

    // ---- Media type, charset, and encoding ----

    [Theory]
    [InlineData("application/x-www-form-urlencoded; charset=iso-8859-1")]
    [InlineData("application/x-www-form-urlencoded; foo=bar")]
    public async Task ANonUtf8FormCharsetOrExtraParameter_IsTheFixed400(string contentType)
    {
        using var http = CreateClientWithBasicAuth();
        var content = new ByteArrayContent(Encoding.ASCII.GetBytes("grant_type=password"));
        content.Headers.TryAddWithoutValidation("Content-Type", contentType);

        using var response = await http.PostAsync("/oauth2/token", content, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(FixedInvalidRequestBody, body);
    }

    [Theory]
    [InlineData("application/json")]
    [InlineData("text/plain")]
    [InlineData("multipart/form-data; boundary=bound")]
    public async Task ANonFormMediaType_KeepsTheActionSelectionRejection(string contentType)
    {
        // A non-form media type never selects the form-consuming action at all, so the request
        // ends in MVC's action-selection 415 exactly as on main: no body is ever read, and this
        // gate adds no new direct response entry point of its own before the shared budget.
        using var http = CreateClientWithBasicAuth();
        var content = new ByteArrayContent(Encoding.ASCII.GetBytes("grant_type=password"));
        content.Headers.TryAddWithoutValidation("Content-Type", contentType);

        using var response = await http.PostAsync("/oauth2/token", content, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    [Fact]
    public async Task AUtf8CharsetDeclaration_IsAdmitted()
    {
        using var http = CreateClientWithBasicAuth();
        var content = new ByteArrayContent(Encoding.ASCII.GetBytes("grant_type=unsupported-probe"));
        content.Headers.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

        using var response = await http.PostAsync("/oauth2/token", content, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("unsupported_grant_type", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACompressedBody_IsTheFixed400()
    {
        using var http = CreateClientWithBasicAuth();
        var content = RawForm(Encoding.ASCII.GetBytes("grant_type=unsupported-probe"));
        content.Headers.TryAddWithoutValidation("Content-Encoding", "gzip");

        using var response = await http.PostAsync("/oauth2/token", content, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(FixedInvalidRequestBody, body);
    }

    // ---- Encoding strictness ----

    [Theory]
    [InlineData("%FF=1")]
    [InlineData("a=%FF")]
    [InlineData("a=%C3%28")]
    [InlineData("a=%")]
    [InlineData("a=%2")]
    [InlineData("a=%G1")]
    public async Task AMalformedPercentOrUtf8Sequence_IsTheFixed400(string body)
    {
        using var http = CreateClientWithBasicAuth();

        using var response = await http.PostAsync(
            "/oauth2/token",
            RawForm(Encoding.ASCII.GetBytes(body)),
            TestContext.Current.CancellationToken);
        var text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(FixedInvalidRequestBody, text);
    }

    [Theory]
    [InlineData("pass%25word", "pass%word")]
    [InlineData("pass+word", "pass word")]
    [InlineData("pass%2Bword", "pass+word")]
    [InlineData("pass%2bword", "pass+word")]
    [InlineData("pass%C3%B6word", "passöword")]
    public async Task Decoding_IsASingleStrictPass(string encoded, string decoded)
    {
        using var http = CreateClientWithBasicAuth();

        using var response = await http.PostAsync(
            "/oauth2/token",
            RawForm(Encoding.UTF8.GetBytes("grant_type=" + encoded)),
            TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        // The dispatch error echoes the once-decoded wire value — proof of exactly one decode.
        Assert.Contains("unsupported_grant_type", body, StringComparison.Ordinal);
        Assert.Contains(decoded, body, StringComparison.Ordinal);
    }

    // ---- No side effects and the shared budget ----

    [Fact]
    public async Task AMalformedSubmission_ConsumesNoCredentialsAndWritesNothing()
    {
        using var http = CreateClientWithBasicAuth();
        int loginHistoryRows;
        int auditRows;
        using (var scope = _fixture.Services.CreateScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<SignaCoreDatabase.IdentityDbContext>();
            loginHistoryRows = await database.LoginHistories.CountAsync(TestContext.Current.CancellationToken);
            auditRows = await database.AuditLogs.CountAsync(TestContext.Current.CancellationToken);
        }

        var payload = Encoding.UTF8.GetBytes(
            "grant_type=password&username=" + IdentityServerFixture.AdminUsername
            + "&password=a-wrong-password&junk=%FF");
        using (var response = await http.PostAsync(
            "/oauth2/token", RawForm(payload), TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(FixedInvalidRequestBody, body);
        }

        using (var scope = _fixture.Services.CreateScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<SignaCoreDatabase.IdentityDbContext>();
            Assert.Equal(
                loginHistoryRows,
                await database.LoginHistories.CountAsync(TestContext.Current.CancellationToken));
            Assert.Equal(
                auditRows,
                await database.AuditLogs.CountAsync(TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task MalformedRequests_StillConsumeTheSourceNetworkBudget()
    {
        using var host = _fixture.WithTestServices(_ => { });
        using var http = host.CreateClient();

        var budget = SignaCoreDatabase.IdentityConstants.OidcTokenRateLimitPerMinute;
        HttpStatusCode last = 0;
        for (var i = 0; i < budget; i++)
        {
            using var response = await http.PostAsync(
                "/oauth2/token", RawForm(OversizedBody(20 * 1024)), TestContext.Current.CancellationToken);
            last = response.StatusCode;
        }

        // Within budget every malformed request answered the fixed 400.
        Assert.Equal(HttpStatusCode.BadRequest, last);

        using var rejected = await http.PostAsync(
            "/oauth2/token", RawForm(OversizedBody(20 * 1024)), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        var body = await rejected.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("temporarily_unavailable", body.GetProperty("error").GetString());
    }

    // ---- Path variants cannot bypass the gate ----

    [Fact]
    public async Task ACasedPathVariant_IsStillGated()
    {
        using var http = CreateClientWithBasicAuth();

        using var response = await http.PostAsync(
            "/OAuth2/Token",
            RawForm(OversizedBody(20 * 1024)),
            TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(FixedInvalidRequestBody, body);
    }

    // ---- Unit-level probes: the reader itself ----

    [Fact]
    public async Task TheReader_ConsumesAtMostOneBytePastTheBound()
    {
        var stream = new ChunkedMemoryStream(OversizedBody(20 * 1024), chunkSize: 1024);
        var (context, next, invoked) = CreateContext("/oauth2/token", stream);

        await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);

        Assert.Equal(BoundedOidcFormReadingMiddleware.MaxReadBytes, stream.TotalRead);
        Assert.Equal(OidcBoundedFormStatus.Malformed, BoundedOidcFormReadingMiddleware.GetStatus(context));
        Assert.True(invoked.Value);
    }

    [Fact]
    public async Task TheReader_IgnoresALyingContentLength_AndParsesAcrossReadBoundaries()
    {
        // A multi-byte UTF-8 character split across single-byte reads must still decode.
        var payload = Encoding.ASCII.GetBytes("grant_type=pass")
            .Concat(new byte[] { 0xC3, 0xB6 })
            .Concat(Encoding.ASCII.GetBytes("word&repeat=1&repeat=2"))
            .ToArray();
        var stream = new ChunkedMemoryStream(payload, chunkSize: 1);
        var (context, next, invoked) = CreateContext("/oauth2/token", stream);
        context.Request.ContentLength = 10; // deliberately wrong: the bound is on bytes read.

        await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);

        Assert.Equal(payload.Length, stream.TotalRead);
        Assert.Equal(OidcBoundedFormStatus.Parsed, BoundedOidcFormReadingMiddleware.GetStatus(context));
        var form = context.Request.Form;
        Assert.Equal("passöword", form["grant_type"].ToString());
        Assert.Equal(2, form["repeat"].Count);
        Assert.Equal("1", form["repeat"][0]);
        Assert.Equal("2", form["repeat"][1]);
    }

    [Fact]
    public async Task TheReader_MapsFailuresToTheFixedMarker()
    {
        var internalCancel = new CancellationTokenSource();
        await internalCancel.CancelAsync();

        var (ioContext, ioNext, _) = CreateContext(
            "/oauth2/revoke", new ThrowingStream(new IOException("synthetic transport failure")));
        await new BoundedOidcFormReadingMiddleware(ioNext).InvokeAsync(ioContext);
        Assert.Equal(OidcBoundedFormStatus.Unavailable, BoundedOidcFormReadingMiddleware.GetStatus(ioContext));

        var (cancelContext, cancelNext, _) = CreateContext(
            "/oauth2/revoke", new ThrowingStream(new OperationCanceledException(internalCancel.Token)));
        await new BoundedOidcFormReadingMiddleware(cancelNext).InvokeAsync(cancelContext);
        Assert.Equal(OidcBoundedFormStatus.Unavailable, BoundedOidcFormReadingMiddleware.GetStatus(cancelContext));

        var (abortedContext, abortedNext, _) = CreateContext(
            "/oauth2/revoke", new ThrowingStream(new OperationCanceledException()));
        var abortedLifetime = new AbortedLifetimeFeature();
        abortedContext.Features.Set<IHttpRequestLifetimeFeature>(abortedLifetime);
        abortedLifetime.Abort();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new BoundedOidcFormReadingMiddleware(abortedNext).InvokeAsync(abortedContext));
    }

    [Theory]
    [InlineData("a=b=c", "a", "b=c")]
    [InlineData("a", "a", "")]
    [InlineData("a=&b=1", "a", "")]
    public async Task TheParser_KeepsTheFrameworkCompatibleShape(string body, string name, string value)
    {
        var (context, next, invoked) = CreateContext(
            "/oauth2/token", new ChunkedMemoryStream(Encoding.ASCII.GetBytes(body), 64));

        await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);

        Assert.Equal(OidcBoundedFormStatus.Parsed, BoundedOidcFormReadingMiddleware.GetStatus(context));
        Assert.Equal(value, context.Request.Form[name].ToString());
    }

    [Fact]
    public async Task TheGate_CoversOnlyItsTwoEndpoints()
    {
        foreach (var path in new[] { "/oauth2/login", "/oauth2/logout/requests", "/api/auth/token" })
        {
            var (context, next, invoked) = CreateContext(
                path, new ChunkedMemoryStream(OversizedBody(20 * 1024), 1024));
            await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);
            Assert.Null(BoundedOidcFormReadingMiddleware.GetStatus(context));
            // Nothing was read: the legacy and login surfaces keep their own readers.
            Assert.Equal(0, ((ChunkedMemoryStream)context.Request.Body).TotalRead);
        }
    }

    // ---- A real Kestrel socket: the chunked host path ----

    [Fact]
    public async Task ARealKestrelHost_RejectsChunkedOversize_AndDispatchesChunkedForms()
    {
        await using var environment = await KestrelSmokeEnvironment.StartAsync();

        using (var rejected = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new StreamContent(new ChunkedMemoryStream(OversizedBody(20 * 1024), 512))
        })
        {
            rejected.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
            rejected.Headers.Authorization = environment.BasicHeader;
            using var response = await environment.Http.SendAsync(rejected, TestContext.Current.CancellationToken);
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(FixedInvalidRequestBody, body);
        }

        using (var dispatched = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new StreamContent(new ChunkedMemoryStream(
                Encoding.ASCII.GetBytes("grant_type=unsupported-probe"), 7))
        })
        {
            dispatched.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
            dispatched.Headers.Authorization = environment.BasicHeader;
            using var response = await environment.Http.SendAsync(dispatched, TestContext.Current.CancellationToken);
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("unsupported_grant_type", body, StringComparison.Ordinal);
        }
    }

    // ---- Driving ----

    private HttpClient CreateClientWithBasicAuth(string secret = IdentityServerFixture.GatewayAppSecret)
    {
        var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{IdentityServerFixture.GatewayAppId}:{secret}")));
        return http;
    }

    private static ByteArrayContent RawForm(byte[] payload)
    {
        var content = new ByteArrayContent(payload);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
        return content;
    }

    private static byte[] ExactBody(string path) => path == "/oauth2/revoke"
        ? Encoding.ASCII.GetBytes("token=synthetic-refresh-token-for-the-bound-probe")
        : PaddingTo(16 * 1024, "grant_type=unsupported-probe&padding=");

    private static byte[] OversizedBody(int size, bool includePostCredentials = false) => PaddingTo(
        size,
        includePostCredentials
            ? $"client_id={IdentityServerFixture.GatewayAppId}&client_secret={IdentityServerFixture.GatewayAppSecret}&grant_type=password&padding="
            : "grant_type=unsupported-probe&padding=");

    private static byte[] PaddingTo(int totalSize, string prefix)
    {
        var payload = Encoding.ASCII.GetBytes(prefix + new string('a', Math.Max(0, totalSize - prefix.Length)));
        Array.Resize(ref payload, totalSize);
        return payload;
    }

    private static (HttpContext Context, RequestDelegate Next, BooleanGate Invoked) CreateContext(
        string path, Stream body)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = path;
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Body = body;
        var invoked = new BooleanGate();
        return (context, _ => { invoked.Value = true; return Task.CompletedTask; }, invoked);
    }

    private sealed class BooleanGate
    {
        public bool Value { get; set; }
    }

    /// <summary>An explicit, deterministically cancellable request lifetime for the unit probes.</summary>
    private sealed class AbortedLifetimeFeature : IHttpRequestLifetimeFeature
    {
        private readonly CancellationTokenSource _source = new();

        public CancellationToken RequestAborted
        {
            get => _source.Token;
            set => throw new NotSupportedException();
        }

        public void Abort() => _source.Cancel();
    }

    /// <summary>A memory stream that hands out fixed-size reads so read boundaries are observable.</summary>
    private sealed class ChunkedMemoryStream(byte[] payload, int chunkSize) : Stream
    {
        private int _position;

        public long TotalRead { get; private set; }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_position >= payload.Length)
            {
                return ValueTask.FromResult(0);
            }

            var take = Math.Min(chunkSize, Math.Min(buffer.Length, payload.Length - _position));
            payload.AsSpan(_position, take).CopyTo(buffer.Span);
            _position += take;
            TotalRead += take;
            return ValueTask.FromResult(take);
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class ThrowingStream(Exception exception) : Stream
    {
        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            throw exception;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>
    /// One product host as a real child process on a real Kestrel socket (not TestServer),
    /// installed and seeded like the shared fixture, so the chunked request path — real chunk
    /// framing, no Content-Length — is exercised end to end through the host's own listener.
    /// </summary>
    private sealed class KestrelSmokeEnvironment : IAsyncDisposable
    {
        private const string AppId = "kestrel-smoke-app";
        private const string AppSecret = "kestrel-smoke-secret";

        private readonly System.Diagnostics.Process _process;
        private readonly string _bootstrapDirectory;
        private readonly string _databasePath;
        private readonly string _logPath;

        private KestrelSmokeEnvironment(
            System.Diagnostics.Process process,
            string bootstrapDirectory,
            string databasePath,
            string logPath)
        {
            _process = process;
            _bootstrapDirectory = bootstrapDirectory;
            _databasePath = databasePath;
            _logPath = logPath;
        }

        public HttpClient Http { get; private set; } = null!;

        public AuthenticationHeaderValue BasicHeader { get; } = new(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{AppId}:{AppSecret}")));

        public static async Task<KestrelSmokeEnvironment> StartAsync()
        {
            var bootstrapDirectory = Path.Combine(
                Path.GetTempPath(), $"signacore-kestrel-{Guid.NewGuid():N}");
            var databasePath = Path.Combine(
                Path.GetTempPath(), $"signacore-kestrel-{Guid.NewGuid():N}.db");
            var logPath = Path.Combine(
                Path.GetTempPath(), $"signacore-kestrel-{Guid.NewGuid():N}.log");
            var connectionString = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
            {
                DataSource = databasePath
            }.ConnectionString;

            var bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
                bootstrapDirectory,
                new DatabaseOptions
                {
                    Provider = "SQLite",
                    ConnectionString = connectionString
                },
                IdentityServerFixture.RootSecret,
                "kestrel_smoke_admin",
                "Kestrel-Smoke-123!");

            var options = new DbContextOptionsBuilder<SignaCoreDatabase.IdentityDbContext>()
                .UseSqlite(connectionString)
                .Options;
            await using (var database = new SignaCoreDatabase.IdentityDbContext(options))
            {
                database.AppRegistrations.Add(new SignaCoreDatabase.Entity.AppRegistrationEntity
                {
                    Id = Guid.NewGuid(),
                    AppId = AppId,
                    AppSecretHash = BCrypt.Net.BCrypt.HashPassword(AppSecret),
                    AppName = "Kestrel Smoke App",
                    IsActive = true,
                    CreatedAt = DateTimeOffset.UtcNow,
                    AudienceMode = SignaCoreDatabase.Entity.AudienceMode.Shared
                });
                await database.SaveChangesAsync(TestContext.Current.CancellationToken);
            }

            var hostDirectory = LocateHostDirectory();
            var port = ReserveFreePort();
            var logStream = new FileStream(logPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo(
                    "dotnet",
                    Path.Combine(hostDirectory, "SignaCore.Host.dll"))
                {
                    WorkingDirectory = hostDirectory,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            process.StartInfo.EnvironmentVariables["Endpoints__Http"] = port.ToString();
            process.StartInfo.EnvironmentVariables["ASPNETCORE_ENVIRONMENT"] = "Development";
            process.StartInfo.EnvironmentVariables["Bootstrap__FilePath"] = bootstrapFilePath;
            process.OutputDataReceived += (_, eventArgs) =>
            {
                if (eventArgs.Data is not null)
                {
                    lock (logStream)
                    {
                        logStream.Write(Encoding.UTF8.GetBytes(eventArgs.Data + "\n"));
                    }
                }
            };
            process.ErrorDataReceived += (_, eventArgs) =>
            {
                if (eventArgs.Data is not null)
                {
                    lock (logStream)
                    {
                        logStream.Write(Encoding.UTF8.GetBytes(eventArgs.Data + "\n"));
                    }
                }
            };

            try
            {
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                await WaitUntilAcceptingAsync(port, process);
            }
            catch
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                    process.Dispose();
                }
                catch
                {
                    // The process never started or already exited.
                }

                logStream.Dispose();
                throw;
            }

            return new KestrelSmokeEnvironment(process, bootstrapDirectory, databasePath, logPath)
            {
                Http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}/") }
            };
        }

        public async ValueTask DisposeAsync()
        {
            Http.Dispose();
            try
            {
                _process.Kill(entireProcessTree: true);
                await _process.WaitForExitAsync(TestContext.Current.CancellationToken);
            }
            catch
            {
                // Best effort: the listener must not outlive the test.
            }

            _process.Dispose();
            foreach (var file in new[] { _databasePath, _databasePath + "-journal", _logPath })
            {
                try
                {
                    if (File.Exists(file))
                    {
                        File.Delete(file);
                    }
                }
                catch (IOException)
                {
                    // Best effort cleanup of this test's isolated files.
                }
            }

            if (Directory.Exists(_bootstrapDirectory))
            {
                Directory.Delete(_bootstrapDirectory, recursive: true);
            }
        }

        /// <summary>The built host next to this test assembly's output directory.</summary>
        private static string LocateHostDirectory()
        {
            var current = new DirectoryInfo(AppContext.BaseDirectory);
            while (current is not null && current.Name != "bin")
            {
                current = current.Parent;
            }

            if (current?.Parent is not { } artifacts)
            {
                throw new InvalidOperationException(
                    "The Kestrel smoke could not locate the artifacts/bin directory.");
            }

            var host = Path.Combine(artifacts.FullName, "bin", "SignaCore.Host", "release");
            if (!File.Exists(Path.Combine(host, "SignaCore.Host.dll")))
            {
                throw new InvalidOperationException(
                    $"The Kestrel smoke host directory is missing: {host}. Build the solution first.");
            }

            return host;
        }

        private static int ReserveFreePort()
        {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                return ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            }
            finally
            {
                listener.Stop();
            }
        }

        private static async Task WaitUntilAcceptingAsync(int port, System.Diagnostics.Process process)
        {
            var deadline = DateTimeOffset.UtcNow.AddSeconds(60);
            while (DateTimeOffset.UtcNow < deadline)
            {
                if (process.HasExited)
                {
                    throw new InvalidOperationException(
                        $"The Kestrel smoke host exited early with code {process.ExitCode}.");
                }

                try
                {
                    using var client = new System.Net.Sockets.TcpClient();
                    await client.ConnectAsync(System.Net.IPAddress.Loopback, port, TestContext.Current.CancellationToken);
                    return;
                }
                catch
                {
                    // Retry until the deadline.
                }

                await Task.Delay(200, TestContext.Current.CancellationToken);
            }

            throw new InvalidOperationException("The Kestrel smoke host did not accept within 60s.");
        }
    }
}
