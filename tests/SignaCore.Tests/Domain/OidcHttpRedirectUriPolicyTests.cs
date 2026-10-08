using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Domain;

/// <summary>
/// The structural redirect-URI policy after ADR 0008: plain http and https are equal inputs in
/// every environment, with no allowlist, environment privilege, or opt-in — only the structural
/// rules, re-applied wherever a stored URI is revalidated.
/// </summary>
public sealed class OidcHttpRedirectUriPolicyTests
{
    [Theory]
    [InlineData("http://10.20.30.40:80/callback?Path=%2f", "http://10.20.30.40/callback?Path=%2f")]
    [InlineData("http://10.20.30.40/callback", "http://10.20.30.40/callback")]
    [InlineData("http://[fd00::1]:8080/Path", "http://[fd00::1]:8080/Path")]
    public void PlainHttpRegistrations_AreCanonicalizedByTheStructuralRules(string input, string expected)
    {
        Assert.Equal(expected, OidcRedirectUriValidator.ValidateAndCanonicalize(input).Value);
        Assert.True(OidcRedirectUriPolicy.Default.Allows(expected));
        Assert.True(OidcRedirectUriPolicy.Default.Allows(input));
    }

    [Theory]
    [InlineData("http://10.20.30.40/callback#fragment")]
    [InlineData("http://user:pass@10.20.30.40/callback")]
    [InlineData("http://10.20.30.40:99999/callback")]
    [InlineData("http://localhost/callback")]
    public void StructurallyInvalidInputs_FailWithoutEcho(string input)
    {
        var error = Assert.Throws<OidcClientConfigurationException>(() =>
            OidcRedirectUriValidator.ValidateAndCanonicalize(input));
        Assert.DoesNotContain(input, error.Message);
        Assert.False(OidcRedirectUriPolicy.Default.Allows(input));
    }

    [Fact]
    public async Task StoredRegistration_GovernsAuthorizationExactly()
    {
        const string uri = "http://10.20.30.40/callback";
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(), AppId = "policy-client", IsActive = true,
            ClientType = OidcClientType.Confidential, AudienceMode = AudienceMode.PerApplication,
            AllowAuthorizationCode = true, AllowedScopes = "openid",
            RedirectUris = [new() { Kind = RedirectUriKind.Redirect, CanonicalUri = uri }]
        };
        var repository = new Mock<IAppRegistrationRepository>();
        repository.Setup(x => x.GetByAppIdWithOidcConfigurationAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(app);
        var parameters = new OidcAuthorizationParameters(new Dictionary<string, IReadOnlyList<string>>
        {
            ["client_id"] = [app.AppId], ["redirect_uri"] = [uri], ["response_type"] = ["code"],
            ["scope"] = ["openid"], ["state"] = ["state-012345678901234567"],
            ["nonce"] = ["nonce-012345678901234567"], ["code_challenge_method"] = ["S256"],
            ["code_challenge"] = ["E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"]
        });
        // A registered plain-HTTP redirect URI authorizes the request exactly as an https one:
        // there is no second policy layer that could disagree with the stored registration.
        Assert.IsType<OidcAuthorizationValidationResult.Accepted>(
            await new OidcAuthorizationRequestValidator(repository.Object).ValidateAsync(
                parameters, TestContext.Current.CancellationToken));
        app.RedirectUris.Clear();
        Assert.IsType<OidcAuthorizationValidationResult.LocalRejection>(
            await new OidcAuthorizationRequestValidator(repository.Object).ValidateAsync(
                parameters, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void RegistrationApplier_AcceptsPlainHttpAndRetainsIdsOnAcceptedConfiguration()
    {
        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), ClientType = OidcClientType.Confidential, IsActive = true };
        var input = new OidcClientConfigurationInput
        {
            AllowAuthorizationCode = true, AllowedScopes = ["openid"], AudienceMode = "PerApplication",
            RedirectUris = ["http://10.20.30.40/callback"], PostLogoutRedirectUris = ["http://10.20.30.40/logout"]
        };
        var change = OidcClientConfigurationApplier.Apply(app, input);
        var ids = app.RedirectUris.Select(x => x.Id).ToArray();
        Assert.Equal(2, change.AddedRegistrations.Count);
        Assert.Empty(OidcClientConfigurationApplier.Apply(app, input).AddedRegistrations);
        Assert.Equal(ids, app.RedirectUris.Select(x => x.Id));
        // Removing one URI needs no relaxed removal policy: every stored URI satisfies the same
        // structural rules the registration path enforced.
        input.PostLogoutRedirectUris = [];
        var cleanup = OidcClientConfigurationApplier.Apply(app, input);
        Assert.Single(cleanup.RemovedRegistrations);
        Assert.Single(app.RedirectUris);
        Assert.True(OidcRedirectUriPolicy.Default.Allows(app.RedirectUris.Single().CanonicalUri));
    }
}
