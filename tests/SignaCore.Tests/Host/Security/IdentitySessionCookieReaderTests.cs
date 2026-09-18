using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Host.Security;

/// <summary>
/// The candidate-id judgement of <see cref="IdentitySessionCookieReader"/>: the identity scheme
/// named explicitly (<c>PS-18</c>), exactly one well-formed session id claim, and <c>null</c> for
/// every other shape the authentication result can take — a failure (an unprotectable cookie), a
/// missing result (no cookie at all), or a missing, duplicated, malformed, or empty claim. The
/// real protected-cookie round trip — including a tampered value and a management-only request —
/// is covered by the identity cookie sharing suites and the authorize reuse HTTP suite; this unit
/// pins the reader's decision boundary over controlled authentication outcomes.
/// </summary>
public sealed class IdentitySessionCookieReaderTests
{
    private static readonly Guid SessionId = Guid.NewGuid();

    [Fact]
    public async Task TryReadSessionIdAsync_WhenAuthenticationFails_ReturnsNull()
    {
        Assert.Null(await new IdentitySessionCookieReader().TryReadSessionIdAsync(
            CreateContext(AuthenticateResult.Fail("The cookie could not be unprotected."))));
    }

    [Fact]
    public async Task TryReadSessionIdAsync_WithNoAuthenticationResult_ReturnsNull()
    {
        Assert.Null(await new IdentitySessionCookieReader().TryReadSessionIdAsync(
            CreateContext(AuthenticateResult.NoResult())));
    }

    [Fact]
    public async Task TryReadSessionIdAsync_WithOneWellFormedClaim_ReturnsTheSessionId()
    {
        Assert.Equal(SessionId, await new IdentitySessionCookieReader().TryReadSessionIdAsync(
            CreateContext(Success(Principal(SessionId.ToString())))));
    }

    [Fact]
    public async Task TryReadSessionIdAsync_WithoutTheSessionIdClaim_ReturnsNull()
    {
        Assert.Null(await new IdentitySessionCookieReader().TryReadSessionIdAsync(CreateContext(
            Success(new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("unrelated", "value")],
                IdentitySessionDefaults.AuthenticationScheme))))));
    }

    [Fact]
    public async Task TryReadSessionIdAsync_WithADuplicatedSessionIdClaim_ReturnsNull()
    {
        Assert.Null(await new IdentitySessionCookieReader().TryReadSessionIdAsync(CreateContext(
            Success(new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(IdentitySessionDefaults.SessionIdClaim, SessionId.ToString()),
                new Claim(IdentitySessionDefaults.SessionIdClaim, Guid.NewGuid().ToString())
            ],
            IdentitySessionDefaults.AuthenticationScheme))))));
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public async Task TryReadSessionIdAsync_WithAMalformedOrEmptyClaimValue_ReturnsNull(string value)
    {
        Assert.Null(await new IdentitySessionCookieReader().TryReadSessionIdAsync(
            CreateContext(Success(Principal(value)))));
    }

    // ---- Harness ----

    private static ClaimsPrincipal Principal(string claimValue) => new(new ClaimsIdentity(
        [new Claim(IdentitySessionDefaults.SessionIdClaim, claimValue)],
        IdentitySessionDefaults.AuthenticationScheme));

    private static AuthenticateResult Success(ClaimsPrincipal principal) =>
        Microsoft.AspNetCore.Authentication.AuthenticateResult.Success(
            new AuthenticationTicket(principal, IdentitySessionDefaults.AuthenticationScheme));

    private static DefaultHttpContext CreateContext(AuthenticateResult result)
    {
        var services = new ServiceCollection()
            .AddAuthenticationCore()
            .AddOptions()
            .Configure<AuthenticationOptions>(options =>
                options.AddScheme(
                    IdentitySessionDefaults.AuthenticationScheme,
                    builder => builder.HandlerType = typeof(StubAuthenticationHandler)))
            .AddSingleton(result);
        return new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
    }

    /// <summary>
    /// Replies with the single registered <see cref="AuthenticateResult"/>: every reader decision
    /// is exercised over a controlled authentication outcome instead of a real cookie payload.
    /// </summary>
    private sealed class StubAuthenticationHandler(AuthenticateResult result) : IAuthenticationHandler
    {
        public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context) =>
            Task.CompletedTask;

        public Task<AuthenticateResult> AuthenticateAsync() => Task.FromResult(result);

        public Task ChallengeAsync(AuthenticationProperties? properties) => Task.CompletedTask;

        public Task ForbidAsync(AuthenticationProperties? properties) => Task.CompletedTask;
    }
}
