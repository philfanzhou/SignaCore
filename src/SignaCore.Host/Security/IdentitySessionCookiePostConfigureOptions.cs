using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace SignaCore.Host.Security;

/// <summary>
/// Pins the identity cookie payload format to the explicit
/// <see cref="IdentitySessionDefaults.DataProtectionPurpose"/>.
/// </summary>
/// <remarks>
/// Without this, the framework derives the purpose from the scheme name; pinning it keeps the
/// protected payload stable under the contract constant instead. The protector is created from the
/// shared <see cref="IDataProtectionProvider"/> — the fixed ServiceMantle application discriminator
/// with the key ring in the shared encrypted store — so cross-instance reads work exactly like the
/// management cookie, and isolation from it exists only through this distinct purpose. This must
/// be registered before the cookie scheme itself: the framework post-configuration only fills a
/// format that is still unset.
/// </remarks>
internal sealed class IdentitySessionCookiePostConfigureOptions(
    IDataProtectionProvider dataProtectionProvider)
    : IPostConfigureOptions<CookieAuthenticationOptions>
{
    public void PostConfigure(string? name, CookieAuthenticationOptions options)
    {
        if (!string.Equals(
                name,
                IdentitySessionDefaults.AuthenticationScheme,
                StringComparison.Ordinal))
        {
            return;
        }

        options.TicketDataFormat = new TicketDataFormat(
            dataProtectionProvider.CreateProtector(
                IdentitySessionDefaults.DataProtectionPurpose));
    }
}
