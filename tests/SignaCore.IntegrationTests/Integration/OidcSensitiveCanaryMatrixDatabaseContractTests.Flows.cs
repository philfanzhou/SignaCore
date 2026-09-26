using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database.Entity;
using SignaCore.Host.Security;
using Xunit;
using static SignaCore.Tests.Integration.OidcDatabaseTestSupport;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

public sealed partial class OidcSensitiveCanaryMatrixDatabaseContractTests
{
    private const string PostLogout = "https://bff.shared-budget.test/signed-out";
    private sealed record Flow(string Code, string Cookie);
    private sealed record Tokens(string Access, string Id, string Refresh);

    private static async Task EnableFlowsAsync(Harness harness)
    {
        await using var db = harness.Context();
        var app = await db.AppRegistrations.SingleAsync(x => x.AppId == ClientId, Ct);
        app.AllowRefreshToken = true;
        app.AllowedScopes = "openid profile offline_access";
        db.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(), AppRegistrationId = app.Id,
            Kind = RedirectUriKind.PostLogout, CanonicalUri = PostLogout
        });
        await db.SaveChangesAsync(Ct);
    }

    private static HttpRequestMessage Get(string uri, string? cookie = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        if (cookie is not null) request.Headers.Add("Cookie", IdentitySessionDefaults.CookieName + "=" + cookie);
        return request;
    }

    private static HttpRequestMessage Form(string path, params (string Key, string Value)[] fields) => new(HttpMethod.Post, path)
    {
        Headers = { Authorization = BasicHeader(ClientId, ClientSecret) },
        Content = new FormUrlEncodedContent(fields.Select(field => new KeyValuePair<string, string>(field.Key, field.Value)))
    };

    private static HttpRequestMessage UserInfo(string access) => new(HttpMethod.Get, "/oauth2/userinfo")
    { Headers = { Authorization = new AuthenticationHeaderValue("Bearer", access) } };

    private static string AuthorizeUrl(string state, string nonce) => "/oauth2/authorize?client_id=" + ClientId +
        "&redirect_uri=" + Uri.EscapeDataString(RedirectUri) + "&response_type=code&scope=openid%20profile%20offline_access" +
        "&state=" + state + "&nonce=" + nonce + "&code_challenge=" + CodeChallenge + "&code_challenge_method=S256";

    private static string QueryValue(string uri, string name)
    {
        var query = QueryHelpers.ParseQuery(new Uri(new Uri("https://localhost"), uri).Query);
        Assert.True(query.TryGetValue(name, out var value) && !string.IsNullOrEmpty(value), "A contracted query field was absent.");
        return value.ToString();
    }

    private static async Task<(LoginSession Session, string State, string Nonce)> BeginAsync(
        Harness harness, TestHost host, OidcCanaryScan scan)
    {
        var state = scan.New("state");
        var nonce = scan.New("nonce");
        using var authorize = await host.Client.GetAsync(AuthorizeUrl(state, nonce), Ct);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var uri = authorize.Headers.Location!.ToString();
        var handle = scan.Add("continuation", QueryValue(uri, "login_handle"));
        await CaptureAsync(scan, authorize, HttpStatusCode.Found, query: new Dictionary<string, string> { ["login_handle"] = handle });
        using var form = await host.Client.GetAsync(uri, Ct);
        Assert.Equal(HttpStatusCode.OK, form.StatusCode);
        var html = await form.Content.ReadAsStringAsync(Ct);
        var token = scan.Add("antiforgery", Regex.Match(html, "name=\"__RequestVerificationToken\" value=\"([^\"]*)\"").Groups[1].Value);
        var cookie = scan.Add("cookie", CookieValueFromHeader(GetSetCookieHeader(form, CookieName)!, CookieName));
        var session = new LoginSession(handle, cookie, token);
        await CaptureAsync(scan, form, HttpStatusCode.OK, login: session, cookies: true);
        await using var db = harness.Context();
        var row = await db.AuthorizationRequests.SingleAsync(x => x.State == state, Ct);
        scan.AllowSnapshot("authorization_requests", "state", row.Id, state);
        scan.AllowSnapshot("authorization_requests", "nonce", row.Id, nonce);
        scan.AllowSnapshot("authorization_requests", "code_challenge", row.Id, CodeChallenge);
        return (session, state, nonce);
    }

    private static async Task<Flow> LoginAndAuthorizeAsync(Harness harness, TestHost a, TestHost b,
        OidcCanaryScan scan, bool exerciseFailures = false)
    {
        var username = "matrix_user_" + Guid.NewGuid().ToString("N");
        var password = scan.New("password");
        await SeedUserAsync(a.Factory.Services, username, password);
        var begin = await BeginAsync(harness, a, scan);
        if (exerciseFailures)
        {
            using var failure = await a.Client.SendAsync(CreateLoginPost(fields: LoginFields(begin.Session, username, scan.New("password")),
                cookieHeader: CookieHeaderFor(begin.Session)), Ct);
            await CaptureAsync(scan, failure, HttpStatusCode.OK, login: begin.Session);
            foreach (var url in new[]
                     {
                         AuthorizeUrl(begin.State, begin.Nonce).Replace(ClientId, "unknown-matrix-client", StringComparison.Ordinal),
                         AuthorizeUrl(begin.State, begin.Nonce).Replace(Uri.EscapeDataString(RedirectUri), Uri.EscapeDataString("https://untrusted.test/callback"), StringComparison.Ordinal)
                     })
            {
                using var rejected = await b.Client.GetAsync(url, Ct);
                await CaptureAsync(scan, rejected, HttpStatusCode.BadRequest);
            }
        }
        using var success = await a.Client.SendAsync(CreateLoginPost(fields: LoginFields(begin.Session, username, password),
            cookieHeader: CookieHeaderFor(begin.Session)), Ct);
        Assert.Equal(HttpStatusCode.Found, success.StatusCode);
        var cookie = scan.Add("cookie", CookieValueFromHeader(GetSetCookieHeader(success, IdentitySessionDefaults.CookieName)!, IdentitySessionDefaults.CookieName));
        var loginCode = scan.Add("code", QueryValue(success.Headers.Location!.ToString(), "code"));
        await CaptureAsync(scan, success, HttpStatusCode.Found, query: new Dictionary<string, string> { ["code"] = loginCode, ["state"] = begin.State }, cookies: true);
        var state = scan.New("state");
        var nonce = scan.New("nonce");
        using var authorized = await b.Client.SendAsync(Get(AuthorizeUrl(state, nonce), cookie), Ct);
        Assert.Equal(HttpStatusCode.Found, authorized.StatusCode);
        var code = scan.Add("code", QueryValue(authorized.Headers.Location!.ToString(), "code"));
        await CaptureAsync(scan, authorized, HttpStatusCode.Found, query: new Dictionary<string, string> { ["code"] = code, ["state"] = state });
        await using var db = harness.Context();
        foreach (var expectedNonce in new[] { begin.Nonce, nonce })
        {
            var row = await db.AuthorizationCodes.SingleAsync(x => x.Nonce == expectedNonce, Ct);
            scan.AllowSnapshot("authorization_codes", "nonce", row.Id, expectedNonce);
            scan.AllowSnapshot("authorization_codes", "code_challenge", row.Id, CodeChallenge);
        }
        return new Flow(code, cookie);
    }

    private static async Task<Tokens> ExchangeAsync(TestHost host, OidcCanaryScan scan, string code)
    {
        using var response = await host.Client.SendAsync(OidcAttackRateLimitDatabaseContractTests.Redeem(code), Ct);
        return await TokensAsync(scan, response);
    }

    private static async Task<Tokens> TokensAsync(OidcCanaryScan scan, HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        var allowed = new Dictionary<string, string>();
        foreach (var field in new[] { "access_token", "id_token", "refresh_token" })
            allowed[field] = scan.Add(field, json.RootElement.GetProperty(field).GetString()!);
        await CaptureAsync(scan, response, HttpStatusCode.OK, json: allowed);
        return new Tokens(allowed["access_token"], allowed["id_token"], allowed["refresh_token"]);
    }

    private static async Task AuditRollbackAsync(Harness harness, TestHost normal, TestHost fault, OidcCanaryScan scan)
    {
        var username = "rollback_" + Guid.NewGuid().ToString("N");
        var password = scan.New("password");
        var accountId = await SeedUserAsync(fault.Factory.Services, username, password);
        var begin = await BeginAsync(harness, normal, scan);
        using var response = await fault.Client.SendAsync(CreateLoginPost(fields: LoginFields(begin.Session, username, password),
            cookieHeader: CookieHeaderFor(begin.Session)), Ct);
        await CaptureAsync(scan, response, HttpStatusCode.InternalServerError);
        await using var db = harness.Context();
        Assert.False(await db.IdentitySessions.AnyAsync(x => x.AccountId == accountId, Ct));
        Assert.Null((await db.AuthorizationRequests.SingleAsync(x => x.State == begin.State, Ct)).ConsumedAt);
    }

    /// <summary>Remove only exact contracted fields; scan every other field and header.</summary>
    private static async Task CaptureAsync(OidcCanaryScan scan, HttpResponseMessage response, HttpStatusCode expected,
        Dictionary<string, string>? query = null, Dictionary<string, string>? json = null,
        LoginSession? login = null, bool cookies = false)
    {
        Assert.Equal(expected, response.StatusCode);
        foreach (var header in response.Headers.Concat(response.Content.Headers))
        foreach (var value in header.Value)
        {
            var text = value;
            if (header.Key.Equals("Location", StringComparison.OrdinalIgnoreCase) && query is not null)
                text = RemoveQueryValues(value, query);
            if (header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase) && cookies)
            {
                foreach (var name in new[] { CookieName, IdentitySessionDefaults.CookieName })
                {
                    if (!value.StartsWith(name + "=", StringComparison.Ordinal)) continue;
                    var end = value.IndexOf(';');
                    Assert.True(end > name.Length, "Malformed contracted cookie.");
                    var envelope = value[(name.Length + 1)..end];
                    if (envelope.Length > 0) scan.Add("cookie", envelope);
                    text = name + "=[contract]" + value[end..];
                }
            }
            scan.Capture("http", text);
        }
        var body = await response.Content.ReadAsStringAsync(Ct);
        if (json is not null)
        {
            using var document = JsonDocument.Parse(body);
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (json.TryGetValue(property.Name, out var allowed))
                    Assert.True(property.Value.GetString() == allowed, "Contracted JSON value differed.");
                else scan.Capture("http", property.Value.ToString());
            }
        }
        else
        {
            if (login is not null)
            {
                foreach (var (field, value) in new[] { ("login_handle", login.Handle), ("__RequestVerificationToken", login.Token) })
                {
                    // Framework can reissue an antiforgery token on the failure page. Enroll
                    // its exact hidden-field value before removing just that attribute.
                    var pattern = "(name=\"" + field + "\" value=\")([^\"]*)(\")";
                    body = Regex.Replace(body, pattern, match =>
                    {
                        var actual = WebUtility.HtmlDecode(match.Groups[2].Value);
                        if (field == "login_handle") Assert.True(actual == value, "Continuation changed in the login form.");
                        scan.Add(field == "login_handle" ? "continuation" : "antiforgery", actual);
                        return match.Groups[1].Value + "[contract]" + match.Groups[3].Value;
                    });
                }
            }
            scan.Capture("http", body);
        }
        if (expected is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable)
            await AssertFixedRejectionAsync(response, expected);
    }

    private static string RemoveQueryValues(string uri, Dictionary<string, string> allowed)
    {
        var parsed = new Uri(new Uri("https://localhost"), uri);
        var query = QueryHelpers.ParseQuery(parsed.Query);
        var kept = new List<string> { parsed.GetLeftPart(UriPartial.Path), parsed.Fragment };
        foreach (var field in query)
        {
            if (allowed.TryGetValue(field.Key, out var value))
                Assert.True(field.Value.Count == 1 && field.Value[0] == value, "Contracted query value differed.");
            else kept.Add(field.Key + "=" + field.Value);
        }
        return string.Join('|', kept);
    }
}
