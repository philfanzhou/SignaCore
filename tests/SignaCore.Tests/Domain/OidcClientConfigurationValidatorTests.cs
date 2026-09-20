using SignaCore.Database.Entity;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Domain;

public sealed class OidcClientConfigurationValidatorTests
{
    [Fact]
    public void AppRegistrationEntity_UsesFailClosedInteractiveDefaults()
    {
        var application = new AppRegistrationEntity();

        Assert.Equal(OidcClientType.Confidential, application.ClientType);
        Assert.False(application.AllowAuthorizationCode);
        Assert.Equal("openid", application.AllowedScopes);
        Assert.False(application.AllowRefreshToken);
        Assert.Null(application.IdentitySessionMaxAgeSeconds);
        Assert.Empty(application.RedirectUris);
    }

    [Fact]
    public void Validate_CanonicalizesSupportedScopes()
    {
        var result = OidcClientConfigurationValidator.Validate(
            OidcClientType.Confidential,
            allowAuthorizationCode: true,
            ["offline_access", "openid", "profile"],
            allowRefreshToken: true,
            identitySessionMaxAgeSeconds: 43_200,
            AudienceMode.PerApplication,
            ["https://example.com/callback"],
            ["https://example.com/logout"],
            isDevelopment: false);

        Assert.Equal("openid profile offline_access", result.AllowedScopes);
        Assert.Equal(43_200, result.IdentitySessionMaxAgeSeconds);
        Assert.Equal("https://example.com/callback", Assert.Single(result.RedirectUris).Value);
        Assert.Equal("https://example.com/logout", Assert.Single(result.PostLogoutRedirectUris).Value);
    }

    [Theory]
    [MemberData(nameof(InvalidScopes))]
    public void Validate_RejectsInvalidScopes(string[] scopes, bool allowRefreshToken)
    {
        Assert.Throws<OidcClientConfigurationException>(() =>
            ValidateDisabled(scopes: scopes, allowRefreshToken: allowRefreshToken));
    }

    public static TheoryData<string[], bool> InvalidScopes => new()
    {
        { [], false },
        { ["profile"], false },
        { ["openid", "email"], false },
        { ["openid", "openid"], false },
        { ["openid", "offline_access"], false }
    };

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(43_201)]
    public void Validate_RejectsInvalidIdentitySessionMaximumAge(int value)
    {
        Assert.Throws<OidcClientConfigurationException>(() =>
            ValidateDisabled(identitySessionMaxAgeSeconds: value));
    }

    [Fact]
    public void Validate_RejectsCodeFlowWithSharedAudience()
    {
        Assert.Throws<OidcClientConfigurationException>(() =>
            ValidateEnabled(audienceMode: AudienceMode.Shared));
    }

    [Fact]
    public void Validate_RejectsCodeFlowWithoutRedirectUri()
    {
        Assert.Throws<OidcClientConfigurationException>(() =>
            ValidateEnabled(redirectUris: []));
    }

    [Fact]
    public void Validate_RejectsActionablePublicClient()
    {
        Assert.Throws<OidcClientConfigurationException>(() =>
            ValidateEnabled(clientType: OidcClientType.Public));
        Assert.Throws<OidcClientConfigurationException>(() =>
            ValidateDisabled(
                clientType: OidcClientType.Public,
                allowRefreshToken: true));
    }

    [Fact]
    public void Validate_AllowsReservedPublicClientWhenFailClosed()
    {
        var result = ValidateDisabled(clientType: OidcClientType.Public);

        Assert.Equal(OidcClientType.Public, result.ClientType);
        Assert.False(result.AllowAuthorizationCode);
        Assert.False(result.AllowRefreshToken);
    }

    /// <summary>
    /// The conversion policy: an existing Confidential client is never downgraded to Public, even
    /// when the requested Public target is itself fail closed. This is the acceptance that a
    /// modification request cannot strip a client's secret-bearing class.
    /// </summary>
    [Fact]
    public void Validate_RejectsTheConfidentialToPublicDowngrade()
    {
        var exception = Assert.Throws<OidcClientConfigurationException>(() =>
            OidcClientConfigurationValidator.Validate(
                OidcClientType.Public,
                allowAuthorizationCode: false,
                ["openid"],
                allowRefreshToken: false,
                identitySessionMaxAgeSeconds: null,
                AudienceMode.Shared,
                [],
                [],
                isDevelopment: false,
                currentClientType: OidcClientType.Confidential));
        Assert.Contains("conversion", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The upgrade direction is explicit and allowed; the caller mints the secret.</summary>
    [Fact]
    public void Validate_AllowsThePublicToConfidentialUpgrade()
    {
        var result = OidcClientConfigurationValidator.Validate(
            OidcClientType.Confidential,
            allowAuthorizationCode: false,
            ["openid"],
            allowRefreshToken: false,
            identitySessionMaxAgeSeconds: null,
            AudienceMode.Shared,
            [],
            [],
            isDevelopment: false,
            currentClientType: OidcClientType.Public);

        Assert.Equal(OidcClientType.Confidential, result.ClientType);
    }

    /// <summary>
    /// A creation context (no current type) may target Public directly — the downgrade rule is a
    /// transition rule, not a ban on Public registrations.
    /// </summary>
    [Fact]
    public void Validate_AllowsAPublicTargetWithNoCurrentType()
    {
        var result = OidcClientConfigurationValidator.Validate(
            OidcClientType.Public,
            allowAuthorizationCode: false,
            ["openid"],
            allowRefreshToken: false,
            identitySessionMaxAgeSeconds: null,
            AudienceMode.Shared,
            [],
            [],
            isDevelopment: false);

        Assert.Equal(OidcClientType.Public, result.ClientType);
    }

    private static SignaCore.Domain.Models.ValidatedOidcClientConfiguration ValidateEnabled(
        OidcClientType clientType = OidcClientType.Confidential,
        AudienceMode audienceMode = AudienceMode.PerApplication,
        string[]? redirectUris = null)
    {
        return OidcClientConfigurationValidator.Validate(
            clientType,
            allowAuthorizationCode: true,
            ["openid"],
            allowRefreshToken: false,
            identitySessionMaxAgeSeconds: null,
            audienceMode,
            redirectUris ?? ["https://example.com/callback"],
            [],
            isDevelopment: false);
    }

    private static SignaCore.Domain.Models.ValidatedOidcClientConfiguration ValidateDisabled(
        OidcClientType clientType = OidcClientType.Confidential,
        string[]? scopes = null,
        bool allowRefreshToken = false,
        int? identitySessionMaxAgeSeconds = null)
    {
        return OidcClientConfigurationValidator.Validate(
            clientType,
            allowAuthorizationCode: false,
            scopes ?? ["openid"],
            allowRefreshToken,
            identitySessionMaxAgeSeconds,
            AudienceMode.Shared,
            [],
            [],
            isDevelopment: false);
    }
}
