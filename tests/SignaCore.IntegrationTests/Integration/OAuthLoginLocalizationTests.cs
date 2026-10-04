using System.Net;
using System.Text.RegularExpressions;
using SignaCore.Database;
using SignaCore.Host.Security;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The <c>zh-CN</c>/<c>en</c> hosted login page and its same-origin stylesheet (ADR 0006, #442):
/// the language comes from <c>Accept-Language</c> only, the form contract is identical in both
/// languages, each language keeps one byte-identical local error page and one byte-identical
/// credential-failure page, every HTML answer varies on <c>Accept-Language</c>, and the stylesheet
/// route is anonymous, cacheable, and self-contained.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed partial class OAuthLoginLocalizationTests : IClassFixture<IdentityServerFixture>
{
    private const string ActiveUser = "l10n_active_user";
    private const string ActivePassword = "L10n-Active-123!";
    private const string DisabledUser = "l10n_disabled_user";
    private const string DisabledPassword = "L10n-Disabled-123!";
    private const string LockedUser = "l10n_locked_user";
    private const string LockedPassword = "L10n-Locked-123!";
    private const string UnknownUser = "l10n-unknown-user";

    private readonly IdentityServerFixture _fixture;

    public OAuthLoginLocalizationTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [GeneratedRegex("<(?:form|input|button)[^>]*>")]
    private static partial Regex FormControlPattern();

    [Theory]
    [InlineData("zh-CN")]
    [InlineData("zh")]
    [InlineData("zh-TW")]
    [InlineData("ZH-cn")]
    [InlineData("zh-Hans-CN,zh;q=0.9,en;q=0.8")]
    [InlineData("fr, zh;q=0.5")]
    public async Task ChineseAcceptLanguage_RendersTheChinesePage(string acceptLanguage)
    {
        var body = await RenderFormAsync(acceptLanguage);

        Assert.StartsWith("<!DOCTYPE html><html lang=\"zh-CN\">", body, StringComparison.Ordinal);
        Assert.Contains("<title>登录</title>", body, StringComparison.Ordinal);
        Assert.Contains("<label for=\"username\">用户名</label>", body, StringComparison.Ordinal);
        Assert.Contains("<label for=\"password\">密码</label>", body, StringComparison.Ordinal);
        Assert.Contains(">取消</button>", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Sign in", body, StringComparison.Ordinal);
        AssertLoginFormValidationMarkup(body);
    }

    [Theory]
    [InlineData("en-US")]
    [InlineData(null)]
    [InlineData("*")]
    [InlineData("zh;q=0")]
    [InlineData("en-US,en;q=0.9,zh-CN;q=0.8")]
    [InlineData("garbage;zh")]
    [InlineData("zh-CN;q=abc, en")]
    [InlineData("zh-CN;q=1.5")]
    public async Task EveryOtherAcceptLanguage_RendersTheEnglishPage(string? acceptLanguage)
    {
        var body = await RenderFormAsync(acceptLanguage);

        Assert.StartsWith("<!DOCTYPE html><html lang=\"en\">", body, StringComparison.Ordinal);
        Assert.Contains("<title>Sign in</title>", body, StringComparison.Ordinal);
        Assert.Contains("<label for=\"username\">Username</label>", body, StringComparison.Ordinal);
        Assert.DoesNotContain("登录", body, StringComparison.Ordinal);
        AssertLoginFormValidationMarkup(body);
    }

    [Fact]
    public async Task BothLanguages_ShareTheExactFormContract()
    {
        var handle = await SeedContinuationAsync(_fixture.Services);
        using var client = _fixture.CreateHttpClient();

        using var english = await GetFormAsync(client, handle, "en");
        using var chinese = await GetFormAsync(client, handle, "zh-CN");
        var englishBody = await english.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var chineseBody = await chinese.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        // Hidden fields, field names, field order, and button names/values are identical; only the
        // per-render antiforgery token value differs.
        Assert.Equal(FormControls(englishBody), FormControls(chineseBody));
        Assert.Equal(
            english.Headers.GetValues("Content-Security-Policy").Single(),
            chinese.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal(
            ExpectedFormContentSecurityPolicy("https://bff.login.test"),
            chinese.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Contains($"href=\"{StylesheetPath}\"", chineseBody, StringComparison.Ordinal);
        Assert.Contains(
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            chineseBody,
            StringComparison.Ordinal);
        foreach (var response in new[] { english, chinese })
        {
            Assert.Equal("Accept-Language", Assert.Single(response.Headers.Vary));
        }
    }

    [Fact]
    public async Task OnlyAcceptLanguage_SelectsTheLanguage()
    {
        var handle = await SeedContinuationAsync(_fixture.Services);
        using var client = _fixture.CreateHttpClient();

        // A culture cookie or any other cookie never changes the language.
        using (var request = new HttpRequestMessage(HttpMethod.Get, $"/oauth2/login?login_handle={handle}"))
        {
            request.Headers.TryAddWithoutValidation("Accept-Language", "en");
            request.Headers.TryAddWithoutValidation(
                "Cookie", ".AspNetCore.Culture=c%3Dzh-CN%7Cuic%3Dzh-CN; lang=zh-CN");
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.StartsWith("<!DOCTYPE html><html lang=\"en\">", body, StringComparison.Ordinal);
        }

        // A language query field is a structural rejection, rendered in the header's language.
        using (var request = new HttpRequestMessage(
                   HttpMethod.Get, $"/oauth2/login?login_handle={handle}&ui_locales=zh-CN"))
        {
            request.Headers.TryAddWithoutValidation("Accept-Language", "en");
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(
                EnglishLocalErrorPage,
                await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        using (var request = new HttpRequestMessage(
                   HttpMethod.Get, $"/oauth2/login?login_handle={handle}&ui_locales=en"))
        {
            request.Headers.TryAddWithoutValidation("Accept-Language", "zh-CN");
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal(
                ChineseLocalErrorPage,
                await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }
    }

    [Theory]
    [InlineData("zh-CN", true)]
    [InlineData("en", false)]
    public async Task EveryLocalRejection_IsOneByteIdenticalPagePerLanguage(string acceptLanguage, bool chinese)
    {
        using var client = _fixture.CreateHttpClient();
        var session = await BeginLoginAsync(_fixture.Services, client);
        var expected = chinese ? ChineseLocalErrorPage : EnglishLocalErrorPage;

        var requests = new List<HttpRequestMessage>
        {
            // Structure: an unknown handle on GET, a query string on POST, a non-form media type,
            // and an unknown field.
            new(HttpMethod.Get, $"/oauth2/login?login_handle={RandomHandle()}"),
            CreateLoginPost(fields: LoginFields(session, ActiveUser, ActivePassword),
                cookieHeader: CookieHeaderFor(session), query: "?x=1"),
            CreateLoginPost(fields: LoginFields(session, ActiveUser, ActivePassword),
                cookieHeader: CookieHeaderFor(session), contentType: "text/plain"),
            CreateLoginPost(
                fields: [.. LoginFields(session, ActiveUser, ActivePassword), new("ui_locales", "zh-CN")],
                cookieHeader: CookieHeaderFor(session)),
            // Handle: unknown handle on POST.
            CreateLoginPost(
                fields: LoginFields(session with { Handle = RandomHandle() }, ActiveUser, ActivePassword),
                cookieHeader: CookieHeaderFor(session)),
            // Action: an unknown value.
            CreateLoginPost(
                fields:
                [
                    new("login_handle", session.Handle),
                    new(LoginAntiforgeryDefaults.TokenFieldName, session.Token),
                    new(ActionFieldName, "register"),
                ],
                cookieHeader: CookieHeaderFor(session)),
            // Antiforgery: a tampered request token.
            CreateLoginPost(
                fields: LoginFields(session with { Token = TamperLastCharacter(session.Token) }, ActiveUser, ActivePassword),
                cookieHeader: CookieHeaderFor(session)),
            // Credential field: an over-limit username.
            CreateLoginPost(
                fields: LoginFields(session, new string('u', 101), ActivePassword),
                cookieHeader: CookieHeaderFor(session)),
        };

        var bodies = new List<string>();
        foreach (var request in requests)
        {
            using (request)
            {
                request.Headers.TryAddWithoutValidation("Accept-Language", acceptLanguage);
                using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
                Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
                AssertLoginSecurityHeaders(response);
                Assert.Equal("Accept-Language", Assert.Single(response.Headers.Vary));
                Assert.Null(GetSetCookieHeader(response, CookieName));
                bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            }
        }

        Assert.All(bodies, body => Assert.Equal(expected, body));
        AssertOnlyStylesheetReference(expected);
        Assert.DoesNotContain(session.Handle, expected, StringComparison.Ordinal);
        Assert.DoesNotContain(session.Token, expected, StringComparison.Ordinal);
        Assert.DoesNotContain(ActiveUser, expected, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("zh-CN", "登录失败。请检查用户名和密码后重试。")]
    [InlineData("en", "Sign-in failed. Check your username and password and try again.")]
    public async Task TheFourCredentialFailures_AreByteIdenticalPerLanguage(string acceptLanguage, string notice)
    {
        var suffix = acceptLanguage == "en" ? "_en" : "_zh";
        await SeedUserAsync(_fixture.Services, ActiveUser + suffix, ActivePassword);
        await SeedUserAsync(_fixture.Services, DisabledUser + suffix, DisabledPassword, isActive: false);
        await SeedUserAsync(_fixture.Services, LockedUser + suffix, LockedPassword);
        await SeedLoginAttemptAsync(
            _fixture.Services,
            LockedUser + suffix,
            failedAttempts: IdentityConstants.MaxFailedLoginAttempts,
            lockoutUntil: DateTimeOffset.UtcNow.AddMinutes(IdentityConstants.LoginLockoutMinutes));

        using var client = _fixture.CreateHttpClient();
        var session = await BeginLoginAsync(_fixture.Services, client);
        var submissions = new (string Username, string Password)[]
        {
            (UnknownUser + suffix, "Does-Not-Matter-1!"),
            (ActiveUser + suffix, "Wrong-Password-1!"),
            (DisabledUser + suffix, DisabledPassword),
            (LockedUser + suffix, LockedPassword),
        };

        var bodies = new List<string>();
        var headers = new List<IReadOnlyList<KeyValuePair<string, string>>>();
        foreach (var (username, password) in submissions)
        {
            using var request = CreateLoginPost(
                fields: LoginFields(session, username, password),
                cookieHeader: CookieHeaderFor(session),
                correlationId: FixedCorrelationId);
            request.Headers.TryAddWithoutValidation("Accept-Language", acceptLanguage);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            AssertLoginSecurityHeaders(response, ExpectedFormContentSecurityPolicy("https://bff.login.test"));
            Assert.Equal("Accept-Language", Assert.Single(response.Headers.Vary));
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            headers.Add(HeaderSnapshot(response));
        }

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
        Assert.All(headers, header => Assert.Equal(headers[0], header));
        Assert.Contains($"<p role=\"alert\" id=\"password-notice\" class=\"notice\">{notice}</p>", bodies[0], StringComparison.Ordinal);
        AssertLoginFormValidationMarkup(bodies[0]);
        foreach (var (username, password) in submissions)
        {
            Assert.DoesNotContain(username, bodies[0], StringComparison.Ordinal);
            Assert.DoesNotContain(password, bodies[0], StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Stylesheet_IsAnonymousCacheableAndSelfContained()
    {
        using var client = _fixture.CreateHttpClient();

        using var plain = await client.GetAsync(StylesheetPath, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, plain.StatusCode);
        Assert.Equal("text/css; charset=utf-8", plain.Content.Headers.ContentType?.ToString());
        Assert.Equal("public, max-age=3600", plain.Headers.CacheControl?.ToString());
        Assert.Equal("nosniff", plain.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.False(plain.Headers.Contains("Set-Cookie"));
        var css = await plain.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.False(string.IsNullOrWhiteSpace(css));
        Assert.DoesNotContain("url(", css, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@import", css, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@font-face", css, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("//", css, StringComparison.Ordinal);
        Assert.Contains("@media (max-width:480px)", css, StringComparison.Ordinal);

        // The route reads no query, cookie, or language header: the answer is the same constant.
        using var request = new HttpRequestMessage(HttpMethod.Get, StylesheetPath + "?login_handle=x&theme=dark");
        request.Headers.TryAddWithoutValidation("Accept-Language", "zh-CN");
        request.Headers.TryAddWithoutValidation("Cookie", $"{CookieName}=not-a-valid-pair");
        using var decorated = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, decorated.StatusCode);
        Assert.False(decorated.Headers.Contains("Set-Cookie"));
        Assert.Equal(css, await decorated.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private async Task<string> RenderFormAsync(string? acceptLanguage)
    {
        var handle = await SeedContinuationAsync(_fixture.Services);
        using var client = _fixture.CreateHttpClient();
        using var response = await GetFormAsync(client, handle, acceptLanguage);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertLoginSecurityHeaders(response, ExpectedFormContentSecurityPolicy("https://bff.login.test"));
        Assert.Equal("Accept-Language", Assert.Single(response.Headers.Vary));
        return await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
    }

    private static async Task<HttpResponseMessage> GetFormAsync(
        HttpClient client,
        string handle,
        string? acceptLanguage)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/oauth2/login?login_handle={handle}");
        if (acceptLanguage is not null)
        {
            request.Headers.TryAddWithoutValidation("Accept-Language", acceptLanguage);
        }

        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static List<string> FormControls(string body) =>
        FormControlPattern().Matches(body)
            .Select(match => Regex.Replace(
                match.Value,
                $"(name=\"{LoginAntiforgeryDefaults.TokenFieldName}\" value=\")[^\"]*\"",
                "$1\""))
            .ToList();
}
