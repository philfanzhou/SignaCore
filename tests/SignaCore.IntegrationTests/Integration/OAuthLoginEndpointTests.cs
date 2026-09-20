using System.Net;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Host.Security;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Wire contract of <c>GET/POST /oauth2/login</c> for every path that must stay local in this
/// slice: the single 400 of <c>EV-03</c>/<c>SC-18</c>, the bounded form render with the
/// <c>PS-19</c> cookie, the strict structure and antiforgery gates of <c>SC-19</c> that never
/// reach the shared Password validator, the unread-credential cancel exit, and the
/// <c>IN-12</c>/<c>IN-13</c> field bounds. The credential outcomes live in
/// <see cref="OAuthLoginCredentialTests"/>.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class OAuthLoginEndpointTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public OAuthLoginEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Acceptance 1: every unusable handle shares one local 400 with zero writes ----

    [Fact]
    public async Task GetWithAnUnusableHandleOrQuery_IsTheSingleLocalErrorWithNoWrites()
    {
        var activeHandle = await SeedContinuationAsync(_fixture.Services);
        var expiredHandle = await SeedContinuationAsync(
            _fixture.Services, createdAt: DateTimeOffset.UtcNow.AddMinutes(-30));
        var consumedHandle = await SeedContinuationAsync(_fixture.Services, consumed: true);
        var before = await DumpLoginTablesAsync(_fixture.Services);

        var urls = new List<string> { "/oauth2/login", "/oauth2/login?login_handle=" };
        urls.AddRange(MalformedHandles(activeHandle)
            .Where(handle => handle.Length > 0)
            .Select(handle => $"/oauth2/login?login_handle={Uri.EscapeDataString(handle)}"));
        urls.Add($"/oauth2/login?login_handle={RandomHandle()}");
        urls.Add($"/oauth2/login?login_handle={expiredHandle}");
        urls.Add($"/oauth2/login?login_handle={consumedHandle}");
        urls.Add($"/oauth2/login?login_handle={activeHandle}&login_handle={activeHandle}");
        urls.Add($"/oauth2/login?login_handle={activeHandle}&extra=1");
        urls.Add("/oauth2/login?extra=1");

        using var client = _fixture.CreateHttpClient();
        var bodies = new List<string>();
        foreach (var url in urls)
        {
            using var response = await client.GetAsync(url, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            AssertLoginSecurityHeaders(response);
            Assert.Null(GetSetCookieHeader(response, CookieName));
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
        // The local page echoes no request value: no submitted handle, no form, no redirect.
        Assert.DoesNotContain(activeHandle, bodies[0], StringComparison.Ordinal);
        Assert.DoesNotContain("login_handle=", bodies[0], StringComparison.Ordinal);
        Assert.DoesNotContain("href", bodies[0], StringComparison.OrdinalIgnoreCase);
        Assert.Equal(before, await DumpLoginTablesAsync(_fixture.Services));
    }

    // ---- Acceptance 2: the successful render ----

    [Fact]
    public async Task GetWithAnActiveHandle_RendersTheBoundedFormAndWritesTheSessionCookieOnce()
    {
        var handle = await SeedContinuationAsync(_fixture.Services);
        using var client = _fixture.CreateHttpClient();
        var url = $"/oauth2/login?login_handle={handle}";

        using var response = await client.GetAsync(url, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertLoginSecurityHeaders(response);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Contains("<form action=\"/oauth2/login\" method=\"post\">", body, StringComparison.Ordinal);
        Assert.Contains($"name=\"login_handle\" value=\"{handle}\"", body, StringComparison.Ordinal);
        var token = ExtractToken(body);
        Assert.Contains("name=\"username\"", body, StringComparison.Ordinal);
        Assert.Contains("type=\"password\"", body, StringComparison.Ordinal);
        Assert.Contains("name=\"action\" value=\"login\"", body, StringComparison.Ordinal);
        Assert.Contains("name=\"action\" value=\"cancel\"", body, StringComparison.Ordinal);

        // The stored continuation snapshot never reaches the page (canary values).
        Assert.DoesNotContain(RegisteredUri, body, StringComparison.Ordinal);
        Assert.DoesNotContain("canary=redirect-uri", body, StringComparison.Ordinal);
        Assert.DoesNotContain("canary-scope-value", body, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryState, body, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryNonce, body, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryChallenge, body, StringComparison.Ordinal);

        var setCookie = GetSetCookieHeader(response, CookieName);
        Assert.NotNull(setCookie);
        Assert.StartsWith($"{CookieName}=", setCookie, StringComparison.Ordinal);
        Assert.Contains("; path=/", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; secure", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; samesite=strict", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("; domain", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("; expires", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("; max-age", setCookie, StringComparison.OrdinalIgnoreCase);
        var cookieValue = CookieValueFromHeader(setCookie!, CookieName);

        // Multi-tab: a GET presenting the still-readable cookie writes no new one, and both
        // rendered tokens pair with the single cookie the browser holds.
        using var secondRequest = new HttpRequestMessage(HttpMethod.Get, url);
        secondRequest.Headers.TryAddWithoutValidation("Cookie", $"{CookieName}={cookieValue}");
        using var secondResponse = await client.SendAsync(secondRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
        Assert.Null(GetSetCookieHeader(secondResponse, CookieName));
        var secondToken = ExtractToken(
            await secondResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.NotEqual(token, secondToken);

        foreach (var tabToken in new[] { token, secondToken })
        {
            using var cancel = CreateLoginPost(
                fields: CancelFields(new LoginSession(handle, cookieValue, tabToken)),
                cookieHeader: $"{CookieName}={cookieValue}");
            using var cancelResponse = await client.SendAsync(cancel, TestContext.Current.CancellationToken);
            // The stored canary snapshot does not revalidate (the client never registered the
            // stored redirect URI), so the cancel exit answers locally without consuming.
            Assert.Equal(HttpStatusCode.BadRequest, cancelResponse.StatusCode);
        }

        // Both tab tokens pair with the single cookie on a revalidatable continuation as well:
        // each tab's cancel reaches the access_denied redirect.
        using var legalClient = _fixture.CreateNonRedirectingHttpClient();
        var legalFirst = await BeginLegalLoginAsync(_fixture.Services, legalClient);
        var legalSecond = await BeginLegalLoginAsync(_fixture.Services, legalClient);
        foreach (var legalSession in new[] { legalFirst, legalSecond })
        {
            using var legalCancel = CreateLoginPost(
                fields: CancelFields(legalSession),
                cookieHeader: CookieHeaderFor(legalSession));
            using var legalResponse = await legalClient.SendAsync(
                legalCancel, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Found, legalResponse.StatusCode);
        }
    }

    // ---- Acceptance 3: structure failures never reach the validator ----

    [Fact]
    public async Task PostStructuralFailures_ShareTheLocalErrorAndNeverReachThePasswordValidator()
    {
        var counter = new CountingPasswordValidator();
        using var factory = _fixture.CreateHostWithCountingValidator(counter);
        using var client = factory.CreateClient();
        var session = await BeginLoginAsync(factory.Services, client);
        var before = await DumpLoginTablesAsync(factory.Services);
        var validBody = BuildEscapedBody(LoginFields(session, "structure_user", "Structure-Pw-1!"));

        var bodies = new List<string>();
        async Task SubmitAsync(HttpRequestMessage request)
        {
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            AssertLoginSecurityHeaders(response);
            Assert.Null(GetSetCookieHeader(response, CookieName));
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        // A query string on the POST.
        await SubmitAsync(CreateLoginPost(rawBody: validBody, query: "?x=1"));
        // Wrong, missing, and non-utf-8 content types.
        await SubmitAsync(CreateLoginPost(rawBody: validBody, contentType: "application/json"));
        await SubmitAsync(CreateLoginPost(rawBody: validBody, contentType: null));
        await SubmitAsync(CreateLoginPost(
            rawBody: validBody, contentType: "application/x-www-form-urlencoded; charset=iso-8859-1"));
        // An unexpected extra parameter fails closed as well.
        await SubmitAsync(CreateLoginPost(
            rawBody: validBody, contentType: "application/x-www-form-urlencoded; boundary=x"));
        // A body beyond the 16 KiB bound.
        await SubmitAsync(CreateLoginPost(fields:
        [
            new("login_handle", session.Handle),
            new("username", "structure_user"),
            new("password", new string('x', 17 * 1024)),
            new(LoginAntiforgeryDefaults.TokenFieldName, session.Token),
            new(ActionFieldName, LoginActionValue),
        ]));
        // Invalid UTF-8 percent sequences and invalid percent escapes.
        await SubmitAsync(CreateLoginPost(rawBody: BuildRawBody(
            ("login_handle", session.Handle),
            ("username", "structure_user"),
            ("password", "%FF%FE"),
            (LoginAntiforgeryDefaults.TokenFieldName, session.Token),
            ("action", LoginActionValue))));
        await SubmitAsync(CreateLoginPost(rawBody: BuildRawBody(
            ("login_handle", session.Handle),
            ("username", "structure_user"),
            ("password", "%zz"),
            (LoginAntiforgeryDefaults.TokenFieldName, session.Token),
            ("action", LoginActionValue))));
        // A segment without '=', an empty segment, a repeated field, and an unknown field.
        await SubmitAsync(CreateLoginPost(rawBody: validBody + "&noequals"));
        await SubmitAsync(CreateLoginPost(rawBody: validBody + "&"));
        await SubmitAsync(CreateLoginPost(rawBody: validBody + "&action=cancel"));
        await SubmitAsync(CreateLoginPost(rawBody: validBody + "&extra=1"));

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
        Assert.Equal(0, counter.Calls);
        Assert.Equal(before, await DumpLoginTablesAsync(factory.Services));
    }

    [Theory]
    [InlineData("application/x-www-form-urlencoded; charset=utf-8")]
    [InlineData("application/x-www-form-urlencoded; charset=UTF-8")]
    public async Task AnExplicitUtf8Charset_IsAdmitted(string contentType)
    {
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginLegalLoginAsync(_fixture.Services, client);

        using var request = CreateLoginPost(
            fields: CancelFields(session),
            contentType: contentType,
            cookieHeader: CookieHeaderFor(session));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // The admitted charset lets the submission reach the cancel exit, which answers with the
        // access_denied redirect for this legally seeded continuation.
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
    }

    // ---- Acceptance 4: antiforgery failures (SC-19 first half) ----

    [Fact]
    public async Task PostAntiforgeryFailures_ShareTheLocalErrorAndWriteNoFailureCount()
    {
        var counter = new CountingPasswordValidator();
        using var factory = _fixture.CreateHostWithCountingValidator(counter);
        using var client = factory.CreateClient();
        var first = await BeginLoginAsync(factory.Services, client);
        var second = await BeginLoginAsync(factory.Services, client);
        var before = await DumpLoginTablesAsync(factory.Services);

        var bodies = new List<string>();
        async Task SubmitAsync(string? cookieValue, string? token)
        {
            var fields = new List<KeyValuePair<string, string>>
            {
                new("login_handle", first.Handle),
                new("username", "antiforgery_user"),
                new("password", "Antiforgery-Pw-1!"),
                new(ActionFieldName, LoginActionValue),
            };
            if (token is not null)
            {
                fields.Add(new(LoginAntiforgeryDefaults.TokenFieldName, token));
            }

            using var request = CreateLoginPost(
                fields: fields,
                cookieHeader: cookieValue is null ? null : $"{CookieName}={cookieValue}");
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            AssertLoginSecurityHeaders(response);
            Assert.Null(GetSetCookieHeader(response, CookieName));
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        // Missing token, missing cookie, and a cross-GET pair.
        await SubmitAsync(first.CookieValue, token: null);
        await SubmitAsync(cookieValue: null, first.Token);
        await SubmitAsync(first.CookieValue, second.Token);
        // Each member of the pair only works in its own position.
        await SubmitAsync(first.CookieValue, first.CookieValue);
        await SubmitAsync(first.Token, first.Token);
        // A tampered token.
        await SubmitAsync(first.CookieValue, TamperLastCharacter(first.Token));
        // A payload protected under the identity session purpose is not an antiforgery cookie.
        using (var scope = factory.Services.CreateScope())
        {
            var foreignPayload = Base64UrlEncode(scope.ServiceProvider
                .GetRequiredService<IDataProtectionProvider>()
                .CreateProtector(IdentitySessionDefaults.DataProtectionPurpose)
                .Protect("identity-session-payload"u8.ToArray()));
            await SubmitAsync(foreignPayload, first.Token);
        }

        // IN-14 bounds: over-length and non-ASCII tokens.
        await SubmitAsync(first.CookieValue, new string('A', LoginAntiforgeryDefaults.MaxTokenLength + 1));
        await SubmitAsync(first.CookieValue, first.Token[..10] + "é");
        await SubmitAsync(first.CookieValue, string.Empty);

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
        Assert.Equal(0, counter.Calls);
        Assert.Equal(before, await DumpLoginTablesAsync(factory.Services));
    }

    // ---- Acceptance 6: the closed action set ----

    [Fact]
    public async Task InvalidActions_ShareTheLocalErrorAndNeverReachThePasswordValidator()
    {
        var counter = new CountingPasswordValidator();
        using var factory = _fixture.CreateHostWithCountingValidator(counter);
        using var client = factory.CreateClient();
        var session = await BeginLoginAsync(factory.Services, client);
        var before = await DumpLoginTablesAsync(factory.Services);

        var bodies = new List<string>();
        foreach (var action in new string?[] { null, string.Empty, "LOGIN", "delete", "Login", " logout " })
        {
            var fields = new List<KeyValuePair<string, string>>
            {
                new("login_handle", session.Handle),
                new("username", "action_user"),
                new("password", "Action-Pw-1!"),
                new(LoginAntiforgeryDefaults.TokenFieldName, session.Token),
            };
            if (action is not null)
            {
                fields.Add(new(ActionFieldName, action));
            }

            using var request = CreateLoginPost(fields: fields, cookieHeader: CookieHeaderFor(session));
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            AssertLoginSecurityHeaders(response);
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
        Assert.Equal(0, counter.Calls);
        Assert.Equal(before, await DumpLoginTablesAsync(factory.Services));
    }

    // ---- Acceptance 7: the cancel exit never reads the credential fields ----

    [Fact]
    public async Task Cancel_NeverReadsCredentialsAndWritesNothingForANonRevalidatableSnapshot()
    {
        var counter = new CountingPasswordValidator();
        using var factory = _fixture.CreateHostWithCountingValidator(counter);
        using var client = factory.CreateClient();
        var session = await BeginLoginAsync(factory.Services, client);
        var before = await DumpLoginTablesAsync(factory.Services);

        var credentialVariants = new (string? Username, string? Password)[]
        {
            (null, null),
            (string.Empty, string.Empty),
            (new string('u', 101), new string('p', 1025)),
            ("%FF-not-even-text", "%%%"),
        };

        var bodies = new List<string>();
        foreach (var (username, password) in credentialVariants)
        {
            var fields = new List<KeyValuePair<string, string>>
            {
                new("login_handle", session.Handle),
                new(LoginAntiforgeryDefaults.TokenFieldName, session.Token),
                new(ActionFieldName, CancelActionValue),
            };
            if (username is not null)
            {
                fields.Add(new("username", username));
            }

            if (password is not null)
            {
                fields.Add(new("password", password));
            }

            using var request = CreateLoginPost(fields: fields, cookieHeader: CookieHeaderFor(session));
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            // This stored canary snapshot does not revalidate (the client never registered the
            // stored redirect URI), so the cancel exit is a local error — and the credential
            // fields never mattered on the way there.
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            AssertLoginSecurityHeaders(response);
            Assert.Null(GetSetCookieHeader(response, CookieName));
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
        Assert.Contains("Invalid login request", bodies[0], StringComparison.Ordinal);
        Assert.Equal(0, counter.Calls);
        // The continuation stays unconsumed and nothing at all was written.
        Assert.Equal(before, await DumpLoginTablesAsync(factory.Services));
    }

    // ---- Acceptance 8: IN-12/IN-13 bounds gate the validator ----

    [Fact]
    public async Task CredentialFieldViolations_ShareTheLocalErrorAndNeverReachThePasswordValidator()
    {
        var counter = new CountingPasswordValidator();
        using var factory = _fixture.CreateHostWithCountingValidator(counter);
        using var client = factory.CreateClient();
        var session = await BeginLoginAsync(factory.Services, client);
        var before = await DumpLoginTablesAsync(factory.Services);

        var bodies = new List<string>();
        async Task SubmitAsync(string? username, string? password)
        {
            var fields = new List<KeyValuePair<string, string>>
            {
                new("login_handle", session.Handle),
                new(LoginAntiforgeryDefaults.TokenFieldName, session.Token),
                new(ActionFieldName, LoginActionValue),
            };
            if (username is not null)
            {
                fields.Add(new("username", username));
            }

            if (password is not null)
            {
                fields.Add(new("password", password));
            }

            using var request = CreateLoginPost(fields: fields, cookieHeader: CookieHeaderFor(session));
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            AssertLoginSecurityHeaders(response);
            Assert.Null(GetSetCookieHeader(response, CookieName));
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        await SubmitAsync(username: null, "Field-Pw-1!");
        await SubmitAsync(string.Empty, "Field-Pw-1!");
        await SubmitAsync(new string('u', 101), "Field-Pw-1!");
        // 60 code units stay inside the 100-unit raw bound but expand past it under the NFC +
        // invariant-uppercase normalization: U+0344 canonically decomposes into two combining
        // characters that do not recompose.
        await SubmitAsync(new string('\u0344', 60), "Field-Pw-1!");
        await SubmitAsync("field_user", password: null);
        await SubmitAsync("field_user", string.Empty);
        await SubmitAsync("field_user", new string('p', 1025));

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
        Assert.Equal(0, counter.Calls);
        Assert.Equal(before, await DumpLoginTablesAsync(factory.Services));
    }

    [Fact]
    public async Task TheValidatorReceivesTheRawUntrimmedFieldValues()
    {
        var counter = new CountingPasswordValidator();
        using var factory = _fixture.CreateHostWithCountingValidator(counter);
        using var client = factory.CreateClient();
        var session = await BeginLoginAsync(factory.Services, client);
        const string paddedUsername = "  Login_Raw_User  ";
        const string paddedPassword = "  Raw-Password-1  ";

        using var request = CreateLoginPost(
            fields: LoginFields(session, paddedUsername, paddedPassword),
            cookieHeader: CookieHeaderFor(session),
            correlationId: FixedCorrelationId);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        Assert.Equal(1, counter.Calls);
        Assert.Equal(paddedUsername, counter.LastRequest!.Username);
        Assert.Equal(paddedPassword, counter.LastRequest.Password);

        // The audit row records the raw submitted username and the validator's internal reason,
        // while the browser only ever sees the generic failure form.
        var history = Assert.Single(await GetLoginHistoriesAsync(factory.Services));
        Assert.Equal(paddedUsername, history.Username);
        Assert.Equal("Wrong username or password", history.FailureReason);
        Assert.Equal("oidc_login", history.AuthMethod);
        Assert.Equal("login_failure", history.EventType);
        Assert.Null(history.AccountId);
        Assert.Equal(AppId, history.AppId);
        Assert.Equal(FixedCorrelationId, history.CorrelationId);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(paddedUsername, body, StringComparison.Ordinal);
        Assert.DoesNotContain(paddedPassword, body, StringComparison.Ordinal);
        Assert.DoesNotContain("Wrong username or password", body, StringComparison.Ordinal);

        // A '+' inside the raw form body decodes to a space before reaching the validator.
        var plusCounter = new CountingPasswordValidator();
        using var plusFactory = _fixture.CreateHostWithCountingValidator(plusCounter);
        using var plusClient = plusFactory.CreateClient();
        var plusSession = await BeginLoginAsync(plusFactory.Services, plusClient);
        using var plusRequest = CreateLoginPost(rawBody: BuildRawBody(
            ("login_handle", plusSession.Handle),
            ("username", "plus_user"),
            ("password", "pa+ss"),
            (LoginAntiforgeryDefaults.TokenFieldName, plusSession.Token),
            ("action", LoginActionValue)),
            cookieHeader: CookieHeaderFor(plusSession));
        using var plusResponse = await plusClient.SendAsync(plusRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, plusResponse.StatusCode);
        Assert.Equal("pa ss", plusCounter.LastRequest!.Password);
    }

    private static string ExtractToken(string body)
    {
        var match = System.Text.RegularExpressions.Regex.Match(
            body, "name=\"__RequestVerificationToken\" value=\"([^\"]*)\"");
        Assert.True(match.Success);
        return match.Groups[1].Value;
    }

    private static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
