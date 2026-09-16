using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Host.Security;

/// <summary>
/// The SignaCore-owned login antiforgery service (canonical PS-19): pairing under the dedicated
/// purpose and its cookie/request sub-purposes, principal independence, constant-time secret
/// comparison over equal-length unprotect results, reuse of a still-readable cookie secret for
/// parallel tabs, and rejection of every foreign, swapped, or malformed value.
/// </summary>
public sealed class LoginAntiforgeryServiceTests : IDisposable
{
    private readonly string _keyDirectory = Path.Combine(
        Path.GetTempPath(), $"signacore-antiforgery-{Guid.NewGuid():N}");

    private ILoginAntiforgeryService CreateService(string applicationName = "antiforgery-tests")
    {
        var services = new ServiceCollection();
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(_keyDirectory))
            .SetApplicationName(applicationName);
        var provider = services.BuildServiceProvider()
            .GetRequiredService<IDataProtectionProvider>();
        return new LoginAntiforgeryService(provider);
    }

    private ILoginAntiforgeryService CreateServiceWithSharedProvider(
        IServiceProvider serviceProvider) =>
        new LoginAntiforgeryService(
            serviceProvider.GetRequiredService<IDataProtectionProvider>());

    [Fact]
    public void AnIssuedPair_Validates()
    {
        var service = CreateService();

        var pair = service.IssuePair(existingCookieValue: null);

        Assert.False(pair.ReusedExistingCookie);
        Assert.True(service.IsValidPair(pair.CookieValue, pair.RequestToken));
    }

    [Fact]
    public void IssuedValues_AreBoundedAsciiBase64Url()
    {
        var pair = CreateService().IssuePair(existingCookieValue: null);

        // IN-14 admits 1-2048 ASCII characters for the form token; the paired cookie value rides
        // the same encoding.
        foreach (var value in new[] { pair.CookieValue, pair.RequestToken })
        {
            Assert.InRange(value.Length, 1, LoginAntiforgeryDefaults.MaxTokenLength);
            Assert.All(value, character => Assert.True(char.IsAscii(character)));
            Assert.DoesNotContain('=', value);
            Assert.DoesNotContain('+', value);
            Assert.DoesNotContain('/', value);
        }
    }

    [Fact]
    public void TwoIssuedPairs_CarryDifferentSecrets()
    {
        var service = CreateService();

        var first = service.IssuePair(existingCookieValue: null);
        var second = service.IssuePair(existingCookieValue: null);

        Assert.NotEqual(first.CookieValue, second.CookieValue);
        Assert.NotEqual(first.RequestToken, second.RequestToken);
        Assert.False(service.IsValidPair(first.CookieValue, second.RequestToken));
        Assert.False(service.IsValidPair(second.CookieValue, first.RequestToken));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SwappedAndTamperedValues_NeverValidate(bool cookieAsToken)
    {
        var service = CreateService();
        var pair = service.IssuePair(existingCookieValue: null);

        // Each value only unprotects under its own sub-purpose, so swapping the pair members fails.
        Assert.False(cookieAsToken
            ? service.IsValidPair(pair.CookieValue, pair.CookieValue)
            : service.IsValidPair(pair.RequestToken, pair.RequestToken));

        var tampered = TamperLastCharacter(pair.RequestToken);
        Assert.False(service.IsValidPair(pair.CookieValue, tampered));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-base64url-!!!")]
    [InlineData("CfDJ8AAAAAAA")]
    [InlineData("非ascii值")]
    public void MalformedValues_FailWithoutThrowing(string value)
    {
        var service = CreateService();
        var pair = service.IssuePair(existingCookieValue: null);

        Assert.False(service.IsValidPair(value, pair.RequestToken));
        Assert.False(service.IsValidPair(pair.CookieValue, value));
    }

    [Fact]
    public void APayloadFromTheIdentitySessionPurpose_IsNotAValidAntiforgeryCookie()
    {
        var services = new ServiceCollection();
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(_keyDirectory))
            .SetApplicationName("antiforgery-tests");
        var serviceProvider = services.BuildServiceProvider();
        var service = CreateServiceWithSharedProvider(serviceProvider);
        var pair = service.IssuePair(existingCookieValue: null);

        // The identity cookie shares the discriminator and the key ring; only the purpose separates
        // the payloads, so its protected blob must never validate as an antiforgery value.
        var foreignPayload = Base64UrlEncode(serviceProvider
            .GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(IdentitySessionDefaults.DataProtectionPurpose)
            .Protect(Encoding.UTF8.GetBytes("identity-session-payload")));

        Assert.False(service.IsValidPair(foreignPayload, pair.RequestToken));
        Assert.False(service.IsValidPair(pair.CookieValue, foreignPayload));
    }

    [Fact]
    public void AUsableExistingCookie_IsReusedSoParallelTabsKeepValidating()
    {
        var service = CreateService();
        var first = service.IssuePair(existingCookieValue: null);

        var second = service.IssuePair(first.CookieValue);
        var third = service.IssuePair(first.CookieValue);

        Assert.True(second.ReusedExistingCookie);
        Assert.Equal(first.CookieValue, second.CookieValue);
        Assert.True(third.ReusedExistingCookie);

        // Every tab's token pairs with the one cookie the browser holds.
        Assert.True(service.IsValidPair(first.CookieValue, first.RequestToken));
        Assert.True(service.IsValidPair(first.CookieValue, second.RequestToken));
        Assert.True(service.IsValidPair(first.CookieValue, third.RequestToken));
        Assert.NotEqual(second.RequestToken, third.RequestToken);
    }

    [Theory]
    [InlineData("garbage-cookie-value")]
    [InlineData("")]
    public void AnUnreadableExistingCookie_IsReplacedByAFreshPair(string presented)
    {
        var service = CreateService();

        var pair = service.IssuePair(presented);

        Assert.False(pair.ReusedExistingCookie);
        Assert.NotEqual(presented, pair.CookieValue);
        Assert.True(service.IsValidPair(pair.CookieValue, pair.RequestToken));
    }

    [Fact]
    public void AnotherKeyRingsPair_DoesNotValidate()
    {
        var issuer = CreateService("antiforgery-instance-a");
        var validator = CreateService("antiforgery-instance-b");
        var pair = issuer.IssuePair(existingCookieValue: null);

        // A different application discriminator derives different protectors, exactly like a
        // deployment with its own key material; the shared production key ring is what makes the
        // cross-instance acceptance work instead.
        Assert.False(validator.IsValidPair(pair.CookieValue, pair.RequestToken));
    }

    private static string TamperLastCharacter(string value)
    {
        var last = value[^1];
        var replacement = last == 'A' ? 'B' : 'A';
        return value[..^1] + replacement;
    }

    private static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public void Dispose()
    {
        if (Directory.Exists(_keyDirectory))
        {
            Directory.Delete(_keyDirectory, recursive: true);
        }
    }
}
