using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace SignaCore.Host.Security;

internal sealed class UnavailableIdentitySessionHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger, UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder), IAuthenticationSignInHandler
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync() => Task.FromResult(AuthenticateResult.NoResult());
    public Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties) =>
        throw new InvalidOperationException("The identity cookie transport is unavailable.");
    public Task SignOutAsync(AuthenticationProperties? properties) => Task.CompletedTask;
}
