using SignaCore.Database.Entity;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

/// <summary>
/// The single place where an interactive OIDC configuration is checked and written. Both the
/// administration API and the <c>bootstrap-apps.json</c> pre-seed go through it, so the rules
/// proved here are the rules both paths obey.
/// </summary>
public class OidcClientConfigurationApplierTests
{
    [Fact]
    public void Apply_WithAValidConfiguration_WritesCanonicalValues()
    {
        var app = Application();

        var change = OidcClientConfigurationApplier.Apply(
            app,
            new OidcClientConfigurationInput
            {
                ClientType = "Confidential",
                AllowAuthorizationCode = true,
                AllowedScopes = ["offline_access", "openid", "profile"],
                AllowRefreshToken = true,
                IdentitySessionMaxAgeSeconds = 3600,
                AudienceMode = "PerApplication",
                RedirectUris = ["HTTPS://BFF.Example.Test:443/Callback"],
                PostLogoutRedirectUris = ["https://bff.example.test"]
            },
            isDevelopment: false);

        Assert.Empty(change.RemovedRegistrations);
        Assert.Equal("openid profile offline_access", app.AllowedScopes);
        Assert.Equal("openid profile offline_access", change.Configuration.AllowedScopes);
        Assert.True(app.AllowAuthorizationCode);
        Assert.True(app.AllowRefreshToken);
        Assert.Equal(3600, app.IdentitySessionMaxAgeSeconds);
        Assert.Equal(AudienceMode.PerApplication, app.AudienceMode);

        // Scheme and host are lowercased and a scheme-default port is dropped, but the path case is
        // preserved: two registrations differing only in path case are two different destinations.
        Assert.Equal(
            "https://bff.example.test/Callback",
            Single(app, RedirectUriKind.Redirect));
        Assert.Equal(
            "https://bff.example.test/",
            Single(app, RedirectUriKind.PostLogout));
    }

    [Theory]
    [InlineData("https://bff.example.test/a%2Fb", "https://bff.example.test/a%2Fb")]
    [InlineData("https://bff.example.test/cb?x=1&y=2", "https://bff.example.test/cb?x=1&y=2")]
    [InlineData("https://bff.example.test/cb/", "https://bff.example.test/cb/")]
    [InlineData("https://bff.example.test?x=1", "https://bff.example.test/?x=1")]
    [InlineData("https://bff.example.test:8443/cb", "https://bff.example.test:8443/cb")]
    public void Apply_PreservesEverythingRegistrationDoesNotNormalise(string submitted, string expected)
    {
        var app = Application();

        OidcClientConfigurationApplier.Apply(app, Policy(submitted), isDevelopment: false);

        Assert.Equal(expected, Single(app, RedirectUriKind.Redirect));
    }

    [Theory]
    [InlineData("http://bff.example.test/cb")]
    [InlineData("https://localhost/cb")]
    [InlineData("https://user:pass@bff.example.test/cb")]
    [InlineData("https://bff.example.test/cb#fragment")]
    [InlineData("https://*.example.test/cb")]
    [InlineData("https://bff.example.test/中文")]
    [InlineData("")]
    [InlineData("/relative/cb")]
    public void Apply_RejectsAUriOutsideRegistrationPolicy(string uri)
    {
        AssertRejected(Policy(uri));
    }

    [Fact]
    public void Apply_RejectsAnOverlongUri()
    {
        AssertRejected(Policy("https://bff.example.test/" + new string('a', 500)));
    }

    [Fact]
    public void Apply_RejectsTheEleventhUriOfAKind()
    {
        var uris = Enumerable.Range(1, 11)
            .Select(index => $"https://bff.example.test/cb{index}")
            .ToList();

        AssertRejected(new OidcClientConfigurationInput
        {
            AllowAuthorizationCode = true,
            AllowedScopes = ["openid"],
            AudienceMode = "PerApplication",
            RedirectUris = uris
        });
    }

    /// <summary>Two values that canonicalise to the same string are one registration, not two.</summary>
    [Fact]
    public void Apply_RejectsValuesThatCollideAfterNormalisation()
    {
        AssertRejected(new OidcClientConfigurationInput
        {
            AllowAuthorizationCode = true,
            AllowedScopes = ["openid"],
            AudienceMode = "PerApplication",
            RedirectUris = ["https://bff.example.test/cb", "HTTPS://BFF.example.test:443/cb"]
        });
    }

    [Fact]
    public void Apply_RejectsAScopeListWithoutOpenId()
    {
        AssertRejected(Policy(allowedScopes: ["profile"]));
    }

    [Fact]
    public void Apply_RejectsAnUnknownScope()
    {
        AssertRejected(Policy(allowedScopes: ["openid", "email"]));
    }

    [Fact]
    public void Apply_RejectsADuplicateScope()
    {
        AssertRejected(Policy(allowedScopes: ["openid", "openid"]));
    }

    [Fact]
    public void Apply_RejectsOfflineAccessWithoutRefreshTokens()
    {
        AssertRejected(Policy(allowedScopes: ["openid", "offline_access"]));
    }

    [Fact]
    public void Apply_RejectsAPublicClientWithACapability()
    {
        AssertRejected(new OidcClientConfigurationInput
        {
            ClientType = "Public",
            AllowAuthorizationCode = true,
            AllowedScopes = ["openid"],
            AudienceMode = "PerApplication",
            RedirectUris = ["https://bff.example.test/cb"]
        });
    }

    [Fact]
    public void Apply_RejectsCodeFlowWithASharedAudience()
    {
        AssertRejected(new OidcClientConfigurationInput
        {
            AllowAuthorizationCode = true,
            AllowedScopes = ["openid"],
            AudienceMode = "Shared",
            RedirectUris = ["https://bff.example.test/cb"]
        });
    }

    [Fact]
    public void Apply_RejectsCodeFlowWithoutARedirectUri()
    {
        AssertRejected(new OidcClientConfigurationInput
        {
            AllowAuthorizationCode = true,
            AllowedScopes = ["openid"],
            AudienceMode = "PerApplication"
        });
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(43201)]
    public void Apply_RejectsAnUnacceptableSessionMaxAge(int seconds)
    {
        AssertRejected(new OidcClientConfigurationInput
        {
            AllowedScopes = ["openid"],
            IdentitySessionMaxAgeSeconds = seconds
        });
    }

    /// <summary>
    /// Unknown names are rejected. Casing and surrounding whitespace are tolerated, which is the
    /// same leniency every other application policy endpoint in this controller already applies to
    /// an administrator-supplied enum name.
    /// </summary>
    [Fact]
    public void Apply_RejectsAnUnknownClientType()
    {
        AssertRejected(new OidcClientConfigurationInput
        {
            ClientType = "Delegated",
            AllowedScopes = ["openid"]
        });
    }

    [Fact]
    public void Apply_AcceptsAClientTypeNameInAnyCase()
    {
        var app = Application();

        OidcClientConfigurationApplier.Apply(
            app,
            new OidcClientConfigurationInput { ClientType = "confidential", AllowedScopes = ["openid"] },
            isDevelopment: false);

        Assert.Equal(OidcClientType.Confidential, app.ClientType);
    }

    [Fact]
    public void Apply_RejectsAnUnknownAudienceMode()
    {
        AssertRejected(new OidcClientConfigurationInput
        {
            AllowedScopes = ["openid"],
            AudienceMode = "Everything"
        });
    }

    /// <summary>
    /// The partial-write counter-proof at its source: one unacceptable member in a request that
    /// would otherwise change five things leaves all five as they were.
    /// </summary>
    [Fact]
    public void Apply_WhenRejected_ChangesNothingOnTheApplication()
    {
        var app = Application();
        OidcClientConfigurationApplier.Apply(
            app,
            new OidcClientConfigurationInput
            {
                AllowAuthorizationCode = true,
                AllowedScopes = ["openid"],
                AudienceMode = "PerApplication",
                RedirectUris = ["https://bff.example.test/first"]
            },
            isDevelopment: false);

        Assert.Throws<OidcClientConfigurationException>(() =>
            OidcClientConfigurationApplier.Apply(
                app,
                new OidcClientConfigurationInput
                {
                    ClientType = "Public",
                    AllowAuthorizationCode = false,
                    AllowedScopes = ["openid", "profile"],
                    AllowRefreshToken = true,
                    IdentitySessionMaxAgeSeconds = 60,
                    AudienceMode = "PerApplication",
                    RedirectUris =
                    [
                        "https://bff.example.test/first",
                        "http://insecure.example.test/second",
                        "https://bff.example.test/third"
                    ]
                },
                isDevelopment: false));

        Assert.True(app.AllowAuthorizationCode);
        Assert.False(app.AllowRefreshToken);
        Assert.Equal("openid", app.AllowedScopes);
        Assert.Equal(OidcClientType.Confidential, app.ClientType);
        Assert.Null(app.IdentitySessionMaxAgeSeconds);
        Assert.Equal("https://bff.example.test/first", Single(app, RedirectUriKind.Redirect));
        Assert.Single(app.RedirectUris);
    }

    /// <summary>
    /// A registration that survives a change keeps its identifier, so an administrator's handle on
    /// a URI does not silently become a different one after an unrelated policy edit.
    /// </summary>
    [Fact]
    public void Apply_KeepsTheIdentifierOfAnUnchangedRegistration()
    {
        var app = Application();
        OidcClientConfigurationApplier.Apply(app, Policy("https://bff.example.test/cb"), isDevelopment: false);
        var originalId = app.RedirectUris.Single().Id;

        var change = OidcClientConfigurationApplier.Apply(
            app,
            new OidcClientConfigurationInput
            {
                AllowAuthorizationCode = true,
                AllowedScopes = ["openid", "profile"],
                AudienceMode = "PerApplication",
                RedirectUris = ["https://bff.example.test/cb"]
            },
            isDevelopment: false);

        Assert.Empty(change.RemovedRegistrations);
        Assert.Empty(change.AddedRegistrations);
        Assert.Equal(originalId, app.RedirectUris.Single().Id);
    }

    [Fact]
    public void Apply_ReportsRemovedRegistrationsForTheCallerToDelete()
    {
        var app = Application();
        OidcClientConfigurationApplier.Apply(
            app,
            new OidcClientConfigurationInput
            {
                AllowAuthorizationCode = true,
                AllowedScopes = ["openid"],
                AudienceMode = "PerApplication",
                RedirectUris = ["https://bff.example.test/a", "https://bff.example.test/b"]
            },
            isDevelopment: false);

        var change = OidcClientConfigurationApplier.Apply(app, Policy("https://bff.example.test/a"), isDevelopment: false);

        Assert.Equal("https://bff.example.test/b", Assert.Single(change.RemovedRegistrations).CanonicalUri);
        Assert.Single(app.RedirectUris);
    }

    /// <summary>Development alone may register a loopback literal over HTTP; never <c>localhost</c>.</summary>
    [Fact]
    public void Apply_AcceptsALoopbackLiteralOnlyInDevelopment()
    {
        var development = Application();
        OidcClientConfigurationApplier.Apply(
            development,
            Policy("http://127.0.0.1:5173/cb"),
            isDevelopment: true);
        Assert.Equal("http://127.0.0.1:5173/cb", Single(development, RedirectUriKind.Redirect));

        var production = Application();
        Assert.Throws<OidcClientConfigurationException>(() =>
            OidcClientConfigurationApplier.Apply(
                production,
                Policy("http://127.0.0.1:5173/cb"),
                isDevelopment: false));
    }

    [Fact]
    public void Apply_WithoutAnAudienceMode_KeepsTheApplicationsCurrentMode()
    {
        var app = Application();
        app.AudienceMode = AudienceMode.PerApplication;

        OidcClientConfigurationApplier.Apply(
            app,
            new OidcClientConfigurationInput { AllowedScopes = ["openid"] },
            isDevelopment: false);

        Assert.Equal(AudienceMode.PerApplication, app.AudienceMode);
    }

    /// <summary>An empty input is the fail-closed upgrade default, not an enabled client.</summary>
    [Fact]
    public void Apply_WithAnEmptyInput_ProducesTheFailClosedDefaults()
    {
        var app = Application();

        OidcClientConfigurationApplier.Apply(
            app,
            new OidcClientConfigurationInput(),
            isDevelopment: false);

        Assert.Equal(OidcClientType.Confidential, app.ClientType);
        Assert.False(app.AllowAuthorizationCode);
        Assert.Equal("openid", app.AllowedScopes);
        Assert.False(app.AllowRefreshToken);
        Assert.Null(app.IdentitySessionMaxAgeSeconds);
        Assert.Empty(app.RedirectUris);
    }

    private static void AssertRejected(OidcClientConfigurationInput input)
    {
        var app = Application();

        Assert.Throws<OidcClientConfigurationException>(() =>
            OidcClientConfigurationApplier.Apply(app, input, isDevelopment: false));

        Assert.Empty(app.RedirectUris);
        Assert.False(app.AllowAuthorizationCode);
        Assert.Equal("openid", app.AllowedScopes);
    }

    private static OidcClientConfigurationInput Policy(
        string? redirectUri = null,
        IReadOnlyList<string>? allowedScopes = null) => new()
        {
            AllowAuthorizationCode = redirectUri is not null,
            AllowedScopes = allowedScopes ?? ["openid"],
            AudienceMode = "PerApplication",
            RedirectUris = redirectUri is null ? [] : [redirectUri]
        };

    private static string Single(AppRegistrationEntity app, RedirectUriKind kind) =>
        app.RedirectUris.Single(uri => uri.Kind == kind).CanonicalUri;

    private static AppRegistrationEntity Application() => new()
    {
        Id = Guid.NewGuid(),
        AppId = "applier-test-app",
        AppName = "Applier Test App",
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };
}
