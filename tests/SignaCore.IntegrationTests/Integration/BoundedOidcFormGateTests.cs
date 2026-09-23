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

using SignaCore.Tests.Integration;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The outer bounded form read of Token, Revoke and Logout preparation: one
/// read of at most 16385 raw bytes ahead of every later stage, one strict UTF-8 single-percent
/// decode, the fixed 400/503 answers after the shared phase and budget admit the request, and no
/// credential, client row, or grant side effect for a rejected body. Caller cancellation outranks
/// parsing and dispatch (observed at entry, after every read return, and before the pipeline
/// continues), the raw read buffer is zeroed on normal, malformed, failed, and cancelled paths
/// alike, and quoted or bare UTF-8 charset declarations are admitted. Unit-level probes drive the
/// middleware directly over counting and retaining streams; the HTTP matrix runs over the real
/// host; one smoke drives a real Kestrel socket with chunked bodies (no Content-Length) — not
/// only TestServer.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed partial class BoundedOidcFormGateTests : IClassFixture<IdentityServerFixture>
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
    [InlineData(16385, "/oauth2/logout/requests", "basic")]
    [InlineData(20 * 1024, "/oauth2/logout/requests", "basic")]
    [InlineData(16385, "/oauth2/logout/requests", "post")]
    [InlineData(16385, "/oauth2/logout/requests", "none")]
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

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task ABodyWithNoContentLength_CannotSmugglePastTheBound(string path)
    {
        using var http = CreateClientWithBasicAuth();
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
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

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task AnOversizedBody_LeaksNoCanary(string path)
    {
        var canary = "synthetic-canary-7c31e9d0b4a2";
        using var http = CreateClientWithBasicAuth();
        var payload = Encoding.ASCII.GetBytes(
            "grant_type=password&username=" + canary + "&password=" + canary + "&padding=" + new string('a', 20_000));

        using var response = await http.PostAsync(
            path, RawForm(payload), TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(FixedInvalidRequestBody, body);
        Assert.DoesNotContain(canary, body, StringComparison.Ordinal);
    }

    // ---- Media type, charset, and encoding ----

    [Theory]
    [InlineData("application/x-www-form-urlencoded; charset=iso-8859-1")]
    [InlineData("application/x-www-form-urlencoded; charset=\"iso-8859-1\"")]
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
    [InlineData("/oauth2/token", "application/json")]
    [InlineData("/oauth2/token", "text/plain")]
    [InlineData("/oauth2/token", "multipart/form-data; boundary=bound")]
    [InlineData("/oauth2/revoke", "application/json")]
    [InlineData("/oauth2/revoke", "multipart/form-data; boundary=bound")]
    [InlineData("/oauth2/logout/requests", "application/json")]
    [InlineData("/oauth2/logout/requests", "text/plain")]
    [InlineData("/oauth2/logout/requests", "multipart/form-data; boundary=bound")]
    public async Task ANonFormMediaType_IsTheFixed400AfterTheSharedBudget(string path, string contentType)
    {
        // The gate owns the media-type decision for these endpoints: a non-form body is the same
        // fixed invalid_request after the shared phase and budget — never an action-selection
        // 415 that would preempt the gate's failure path — and its body is never read.
        using var http = CreateClientWithBasicAuth();
        var content = new ByteArrayContent(Encoding.ASCII.GetBytes("grant_type=password"));
        content.Headers.TryAddWithoutValidation("Content-Type", contentType);

        using var response = await http.PostAsync(path, content, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(FixedInvalidRequestBody, body);
        Assert.Empty(response.Headers.WwwAuthenticate);
    }

    [Theory]
    [InlineData("application/x-www-form-urlencoded; charset=utf-8")]
    [InlineData("application/x-www-form-urlencoded; charset=UTF-8")]
    [InlineData("application/x-www-form-urlencoded; charset=\"utf-8\"")]
    [InlineData("application/x-www-form-urlencoded; charset=\"UTF-8\"")]
    public async Task AUtf8CharsetDeclaration_BareOrQuotedEitherCase_IsAdmitted(string contentType)
    {
        // The parameter grammar allows a quoted value; the framework's own form reader parsed
        // these declarations, so the gate must not turn a legal request into a rejection.
        using var http = CreateClientWithBasicAuth();
        var content = new ByteArrayContent(Encoding.ASCII.GetBytes("grant_type=unsupported-probe"));
        content.Headers.TryAddWithoutValidation("Content-Type", contentType);

        using var response = await http.PostAsync("/oauth2/token", content, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("unsupported_grant_type", body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task ACompressedBody_IsTheFixed400(string path)
    {
        using var http = CreateClientWithBasicAuth();
        var content = RawForm(Encoding.ASCII.GetBytes("grant_type=unsupported-probe"));
        content.Headers.TryAddWithoutValidation("Content-Encoding", "gzip");

        using var response = await http.PostAsync(path, content, TestContext.Current.CancellationToken);
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
            auditRows = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(database, TestContext.Current.CancellationToken)).Count;
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
                (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(database, TestContext.Current.CancellationToken)).Count);
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

    [Fact]
    public async Task TwoConcurrentLegalRequests_NeverShareFormState()
    {
        // Two in-flight submissions with distinct values on an isolated host: each owns its own
        // buffer, parse, and marker, and each dispatch error echoes its own wire value — never
        // the other request's.
        using var host = _fixture.WithTestServices(_ => { });
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{IdentityServerFixture.GatewayAppId}:{IdentityServerFixture.GatewayAppSecret}")));

        var firstSend = http.PostAsync(
            "/oauth2/token",
            RawForm(Encoding.ASCII.GetBytes("grant_type=alpha-probe&pad=" + new string('a', 200))),
            TestContext.Current.CancellationToken);
        var secondSend = http.PostAsync(
            "/oauth2/token",
            RawForm(Encoding.ASCII.GetBytes("grant_type=beta-probe&pad=" + new string('b', 200))),
            TestContext.Current.CancellationToken);        using var first = await firstSend;
        using var second = await secondSend;
        var firstBody = await first.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var secondBody = await second.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Contains("unsupported_grant_type", firstBody, StringComparison.Ordinal);
        Assert.Contains("alpha-probe", firstBody, StringComparison.Ordinal);
        Assert.DoesNotContain("beta-probe", firstBody, StringComparison.Ordinal);
        Assert.Contains("unsupported_grant_type", secondBody, StringComparison.Ordinal);
        Assert.Contains("beta-probe", secondBody, StringComparison.Ordinal);
        Assert.DoesNotContain("alpha-probe", secondBody, StringComparison.Ordinal);
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

    [Fact]
    public async Task ATrailingSlashOnTheWire_NeverReachesTheOriginalDispatch()
    {
        // A trailing-slash POST is gated and bounded like the canonical path and answers the
        // gate's fixed failure — never the original dispatch.
        using var http = CreateClientWithBasicAuth();

        using var response = await http.PostAsync(
            "/oauth2/token/",
            RawForm(OversizedBody(20 * 1024)),
            TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(FixedInvalidRequestBody, body);
        Assert.DoesNotContain("unsupported_grant_type", body, StringComparison.Ordinal);
    }

    // ---- Unit-level probes: the reader itself ----

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task TheReader_ConsumesAtMostOneBytePastTheBound(string path)
    {
        var stream = new ChunkedMemoryStream(OversizedBody(20 * 1024), chunkSize: 1024);
        var (context, next, invoked) = CreateContext(path, stream);

        await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);

        Assert.Equal(BoundedOidcFormReadingMiddleware.MaxReadBytes, stream.TotalRead);
        Assert.Equal(OidcBoundedFormStatus.Malformed, BoundedOidcFormReadingMiddleware.GetStatus(context));
        Assert.True(invoked.Value);
    }

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task TheReader_IgnoresALyingContentLength_AndParsesAcrossReadBoundaries(string path)
    {
        // A multi-byte UTF-8 character split across single-byte reads must still decode.
        var payload = Encoding.ASCII.GetBytes("grant_type=pass")
            .Concat(new byte[] { 0xC3, 0xB6 })
            .Concat(Encoding.ASCII.GetBytes("word&repeat=1&repeat=2"))
            .ToArray();
        var stream = new ChunkedMemoryStream(payload, chunkSize: 1);
        var (context, next, invoked) = CreateContext(path, stream);
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

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task TheReader_MapsFailuresToTheFixedMarker(string path)
    {
        var internalCancel = new CancellationTokenSource();
        await internalCancel.CancelAsync();

        var (ioContext, ioNext, _) = CreateContext(
            path, new ThrowingStream(new IOException("synthetic transport failure")));
        await new BoundedOidcFormReadingMiddleware(ioNext).InvokeAsync(ioContext);
        Assert.Equal(OidcBoundedFormStatus.Unavailable, BoundedOidcFormReadingMiddleware.GetStatus(ioContext));

        var (cancelContext, cancelNext, _) = CreateContext(
            path, new ThrowingStream(new OperationCanceledException(internalCancel.Token)));
        await new BoundedOidcFormReadingMiddleware(cancelNext).InvokeAsync(cancelContext);
        Assert.Equal(OidcBoundedFormStatus.Unavailable, BoundedOidcFormReadingMiddleware.GetStatus(cancelContext));

        var (abortedContext, abortedNext, _) = CreateContext(
            path, new ThrowingStream(new OperationCanceledException()));
        var abortedLifetime = new AbortedLifetimeFeature();
        abortedContext.Features.Set<IHttpRequestLifetimeFeature>(abortedLifetime);
        abortedLifetime.Abort();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new BoundedOidcFormReadingMiddleware(abortedNext).InvokeAsync(abortedContext));
    }

    // ---- Caller cancellation outranks parsing, markers, and downstream ----

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task APreCancelledRequest_NeverReachesAReadOrAnythingDownstream(string path)
    {
        // Pre-cancelled while the stream still holds buffered data it would return: the entry
        // observation must win — no read, no marker, no downstream pipeline.
        var stream = new ChunkedMemoryStream(Encoding.ASCII.GetBytes("grant_type=password"), 4);
        var (context, next, invoked) = CreateContext(path, stream);
        var lifetime = new AbortedLifetimeFeature();
        context.Features.Set<IHttpRequestLifetimeFeature>(lifetime);
        lifetime.Abort();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context));
        Assert.Equal(0, stream.TotalRead);
        Assert.Null(BoundedOidcFormReadingMiddleware.GetStatus(context));
        Assert.False(invoked.Value);
    }

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task ACallerCancelledAtTheEofReturn_IsNeverParsedOrDispatched(string path)
    {
        // The stream delivers the whole body, the caller cancels, and only then does the stream
        // report EOF: the read-return observation must throw — never a Parsed marker, never a
        // downstream call.
        var (context, next, invoked) = CreateContext(path, Stream.Null);
        var lifetime = new AbortedLifetimeFeature();
        context.Features.Set<IHttpRequestLifetimeFeature>(lifetime);
        context.Request.Body = new CancelBeforeEofStream(
            Encoding.ASCII.GetBytes("grant_type=password"),
            lifetime.Abort);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context));
        Assert.Null(BoundedOidcFormReadingMiddleware.GetStatus(context));
        Assert.False(invoked.Value);
    }

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task AnInternalCancellationAfterDataWasRead_IsStillTheUnavailableMarker(string path)
    {
        // The caller stays alive; the stream returns real data and then cancels internally: the
        // classification is Unavailable, and the pipeline continues so the shared budget and the
        // fixed 503 answer still own the response.
        var internalCancel = new CancellationTokenSource();
        await internalCancel.CancelAsync();
        var stream = new PartialThenThrowStream(
            Encoding.ASCII.GetBytes("grant_type=password"),
            new OperationCanceledException(internalCancel.Token));
        var (context, next, invoked) = CreateContext(path, stream);

        await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);

        Assert.Equal(OidcBoundedFormStatus.Unavailable, BoundedOidcFormReadingMiddleware.GetStatus(context));
        Assert.True(invoked.Value);
    }

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task AReadFailureAfterPartialData_ZerosTheRetainedBuffer(string path)
    {
        // The probe retains the very Memory<byte> the reader wrote into: when the second read
        // throws IOException the reader must already have zeroed that memory — the clearing
        // covers the exception path, not only the normal return.
        var stream = new PartialThenThrowStream(
            Encoding.ASCII.GetBytes("grant_type=password&password=secret-value-4f2a"),
            new IOException("synthetic transport failure"));
        var (context, next, _) = CreateContext(path, stream);

        await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);

        Assert.Equal(OidcBoundedFormStatus.Unavailable, BoundedOidcFormReadingMiddleware.GetStatus(context));
        Assert.All(stream.Retained.ToArray(), b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData("/oauth2/token", true)]
    [InlineData("/oauth2/revoke", true)]
    [InlineData("/oauth2/token", false)]
    [InlineData("/oauth2/revoke", false)]
    [InlineData("/oauth2/logout/requests", true)]
    [InlineData("/oauth2/logout/requests", false)]
    public async Task ACallerCancellationAfterPartialData_ZerosTheRetainedBuffer(
        string path, bool ioFailure)
    {
        var lifetime = new AbortedLifetimeFeature();
        var payload = Encoding.ASCII.GetBytes("a=b");
        var stream = new PartialThenThrowStream(
            payload,
            ioFailure ? new IOException("synthetic transport failure") : new OperationCanceledException(),
            lifetime.Abort);
        var (context, next, invoked) = CreateContext(path, stream);
        context.Features.Set<IHttpRequestLifetimeFeature>(lifetime);

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context));
        Assert.Equal(context.RequestAborted, exception.CancellationToken);
        Assert.Equal(2, stream.ReadCalls);
        Assert.Equal(payload.Length, stream.TotalRead);
        Assert.False(stream.Retained.IsEmpty);
        Assert.Null(BoundedOidcFormReadingMiddleware.GetStatus(context));
        Assert.Null(context.Features.Get<IFormFeature>());
        Assert.False(invoked.Value);
        Assert.All(stream.Retained.ToArray(), b => Assert.Equal(0, b));
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
    public async Task TheGate_CoversOnlyItsThreePostEndpoints()
    {
        foreach (var path in new[] { "/oauth2/login", "/oauth2/logout", "/oauth2/logout/requests-extra", "/oauth2/logout/requests//", "/api/auth/token" })
        {
            var (context, next, invoked) = CreateContext(
                path, new ChunkedMemoryStream(OversizedBody(20 * 1024), 1024));
            await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);
            Assert.Null(BoundedOidcFormReadingMiddleware.GetStatus(context));
            // Nothing was read: the legacy and login surfaces keep their own readers.
            Assert.Equal(0, ((ChunkedMemoryStream)context.Request.Body).TotalRead);
        }
    }

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task DownstreamReads_ReuseTheOneCachedForm_AndNeverRereadTheStream(string path)
    {
        // After the gate's single read, every downstream access — Request.Form and
        // ReadFormAsync alike — reuses the cached form feature; the original stream is never
        // read a second time.
        var payload = Encoding.ASCII.GetBytes("grant_type=password&repeat=1&repeat=2");
        var stream = new ChunkedMemoryStream(payload, 8);
        var (context, next, _) = CreateContext(path, stream);
        await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);

        var first = context.Request.Form;
        var second = await context.Request.ReadFormAsync(TestContext.Current.CancellationToken);
        Assert.Same(first, second);
        Assert.Equal(2, second["repeat"].Count);
        Assert.Equal(payload.Length, stream.TotalRead);
    }

    [Theory]
    [InlineData("/oauth2/token/")]
    [InlineData("/oauth2/revoke/")]
    [InlineData("/OAuth2/Revoke/")]
    [InlineData("/oauth2/logout/requests/")]
    [InlineData("/OAuth2/Logout/Requests/")]
    public async Task ATrailingSlashOrCasedVariant_IsStillGatedAndBounded(string path)
    {
        var stream = new ChunkedMemoryStream(OversizedBody(20 * 1024), 1024);
        var (context, next, _) = CreateContext(path, stream);

        await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);

        Assert.Equal(OidcBoundedFormStatus.Malformed, BoundedOidcFormReadingMiddleware.GetStatus(context));
        Assert.Equal(BoundedOidcFormReadingMiddleware.MaxReadBytes, stream.TotalRead);
    }

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/oauth2/logout/requests")]
    public async Task AMountedPathBaseVariant_IsStillGatedAndBounded(string path)
    {
        var stream = new ChunkedMemoryStream(OversizedBody(20 * 1024), 1024);
        var (context, next, _) = CreateContext(path, stream);
        context.Request.PathBase = "/signacore";

        await new BoundedOidcFormReadingMiddleware(next).InvokeAsync(context);

        Assert.Equal(OidcBoundedFormStatus.Malformed, BoundedOidcFormReadingMiddleware.GetStatus(context));
        Assert.Equal(BoundedOidcFormReadingMiddleware.MaxReadBytes, stream.TotalRead);
    }

    // ---- A real Kestrel socket: the chunked host path ----

    [Fact]
    public async Task ARealKestrelHost_RejectsChunkedOversize_AndDispatchesChunkedForms()
    {
        await using var environment = await KestrelSmokeEnvironment.StartAsync();

        foreach (var path in new[] { "/oauth2/token", "/oauth2/logout/requests" })
        {
            using (var rejected = new HttpRequestMessage(HttpMethod.Post, path)
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

            using (var dispatched = new HttpRequestMessage(HttpMethod.Post, path)
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
                Assert.NotEqual(FixedInvalidRequestBody, body);
            }
        }

        var hint = await environment.CreateLogoutHintAsync();
        var prefix = "id_token_hint=" + hint;
        using var exact = new HttpRequestMessage(HttpMethod.Post, "/oauth2/logout/requests")
        {
            Content = new StreamContent(new ChunkedMemoryStream(
                Encoding.ASCII.GetBytes(prefix + new string('&', 16384 - prefix.Length)), 7))
        };
        exact.Headers.Authorization = environment.BasicHeader;
        exact.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
        using var exactResponse = await environment.Http.SendAsync(exact, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, exactResponse.StatusCode);
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

    private static byte[] ExactBody(string path) => path.EndsWith("revoke", StringComparison.OrdinalIgnoreCase)
        ? PaddingTo(16 * 1024, "token=")
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
        public Action? AfterRead { get; init; }
        public Memory<byte> Retained { get; private set; }
        public CancellationToken ObservedToken { get; private set; }

        public long TotalRead { get; private set; }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObservedToken = cancellationToken;
            if (_position >= payload.Length)
            {
                AfterRead?.Invoke();
                return ValueTask.FromResult(0);
            }

            var take = Math.Min(chunkSize, Math.Min(buffer.Length, payload.Length - _position));
            payload.AsSpan(_position, take).CopyTo(buffer.Span);
            _position += take;
            TotalRead += take;
            Retained = buffer[..take];
            AfterRead?.Invoke();
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
    /// A stream that returns its whole payload once, cancels the request lifetime, and only then
    /// reports EOF — the caller abandons the request after the body was handed over.
    /// </summary>
    private sealed class CancelBeforeEofStream(byte[] payload, Action cancel) : Stream
    {
        private bool _delivered;

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_delivered)
            {
                _delivered = true;
                var take = Math.Min(buffer.Length, payload.Length);
                payload.AsSpan(0, take).CopyTo(buffer.Span);
                return ValueTask.FromResult(take);
            }

            cancel();
            return ValueTask.FromResult(0);
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

    /// <summary>
    /// A stream that delivers its payload on the first read and throws on the second, retaining
    /// the <see cref="Memory{T}"/> it handed the bytes into so a test can observe whether the
    /// reader zeroed that buffer afterwards.
    /// </summary>
    private sealed class PartialThenThrowStream(
        byte[] payload, Exception error, Action? beforeFailure = null) : Stream
    {
        private bool _delivered;

        public Memory<byte> Retained { get; private set; }
        public int ReadCalls { get; private set; }
        public int TotalRead { get; private set; }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ReadCalls++;
            if (!_delivered)
            {
                _delivered = true;
                var take = Math.Min(buffer.Length, payload.Length);
                payload.AsSpan(0, take).CopyTo(buffer.Span);
                // Keep the bytes actually written, not the empty tail passed to the next read.
                Retained = buffer[..take];
                TotalRead += take;
                return ValueTask.FromResult(take);
            }

            beforeFailure?.Invoke();
            throw error;
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

        public async Task<string> CreateLogoutHintAsync()
        {
            var options = new DbContextOptionsBuilder<SignaCoreDatabase.IdentityDbContext>()
                .UseSqlite(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder { DataSource = _databasePath }.ConnectionString)
                .Options;
            await using var database = new SignaCoreDatabase.IdentityDbContext(options);
            var app = await database.AppRegistrations.SingleAsync(row => row.AppId == AppId, TestContext.Current.CancellationToken);
            app.AllowAuthorizationCode = true;
            app.ClientType = SignaCoreDatabase.Entity.OidcClientType.Confidential;
            var credential = await database.PasswordCredentials.FirstAsync(TestContext.Current.CancellationToken);
            var now = DateTimeOffset.UtcNow;
            var session = new SignaCoreDatabase.Entity.IdentitySessionEntity
            {
                Id = Guid.NewGuid(), AccountId = credential.AccountId, PasswordCredentialId = credential.Id,
                AuthMethod = "password", AuthTime = now, LastSeenAt = now,
                IdleExpiresAt = now.AddHours(1), AbsoluteExpiresAt = now.AddHours(8)
            };
            database.IdentitySessions.Add(session);
            await database.SaveChangesAsync(TestContext.Current.CancellationToken);
            var key = await database.SecurityKeys.FirstAsync(row => row.IsActive, TestContext.Current.CancellationToken);
            var protector = new SignaCore.Domain.Keys.AesGcmPrivateKeyProtector(
                new SignaCore.Domain.Keys.BootstrapMasterKeyProvider(IdentityServerFixture.RootSecret));
            var privateBytes = protector.Unprotect(key.EncryptedPrivateKeyParams, key.EncryptionSalt);
            using var rsa = System.Security.Cryptography.RSA.Create();
            try { rsa.ImportPkcs8PrivateKey(privateBytes, out _); }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(privateBytes); }
            var discovery = await Http.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration", TestContext.Current.CancellationToken);
            return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(
                new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                    new System.IdentityModel.Tokens.Jwt.JwtHeader(new Microsoft.IdentityModel.Tokens.SigningCredentials(
                        new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa) { KeyId = key.KeyId },
                        Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256)),
                    new System.IdentityModel.Tokens.Jwt.JwtPayload(discovery.GetProperty("issuer").GetString(), AppId,
                        [new System.Security.Claims.Claim("sub", credential.AccountId.ToString("D")),
                         new System.Security.Claims.Claim("sid", session.Id.ToString("D"))],
                        notBefore: null, expires: now.AddMinutes(10).UtcDateTime, issuedAt: now.UtcDateTime)));
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
