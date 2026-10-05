using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Domain;

public sealed class OidcHttpRedirectUriPolicyTests
{
    [Theory]
    [InlineData("http://10.20.30.40:80/callback?Path=%2f", "http://10.20.30.40/callback?Path=%2f")]
    [InlineData("http://10.20.30.40/callback", "http://10.20.30.40/callback")]
    [InlineData("http://[fd00::1]:8080/Path", "http://[fd00::1]:8080/Path")]
    public void AllowedOrigins_AreEffectivePortExact_AndPreserveRequestText(string input, string expected)
    {
        var policy = Policy();
        Assert.Equal(expected, OidcRedirectUriValidator.ValidateAndCanonicalize(input, false, policy).Value);
        Assert.True(policy.Allows(expected));
        Assert.False(OidcRedirectUriPolicy.Default.Allows(expected));
    }

    [Theory]
    [InlineData("http://10.20.30.40:81/callback")]
    [InlineData("http://10.20.30.41/callback")]
    [InlineData("http://010.20.30.40/callback")]
    [InlineData("http://0x0a141e28/callback")]
    [InlineData("http://169.254.1.1/callback")]
    [InlineData("http://[fd00::1]:8081/callback")]
    [InlineData("http://10.20.30.40/callback#fragment")]
    public void UntrustedOrAliasInputs_FailWithoutEcho(string input)
    {
        var error = Assert.Throws<OidcClientConfigurationException>(() =>
            OidcRedirectUriValidator.ValidateAndCanonicalize(input, false, Policy()));
        Assert.DoesNotContain(input, error.Message);
        Assert.False(Policy().Allows(input));
    }

    [Fact]
    public async Task StoredRegistration_DoesNotAuthorizeRemovedPolicy_OrDifferentRequestBytes()
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
        repository.Setup(x => x.GetByAppIdWithOidcConfigurationAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(app);
        var parameters = new OidcAuthorizationParameters(new Dictionary<string, IReadOnlyList<string>>
        {
            ["client_id"] = [app.AppId], ["redirect_uri"] = [uri], ["response_type"] = ["code"],
            ["scope"] = ["openid"], ["state"] = ["state-012345678901234567"],
            ["nonce"] = ["nonce-012345678901234567"], ["code_challenge_method"] = ["S256"],
            ["code_challenge"] = ["E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"]
        });
        Assert.IsType<OidcAuthorizationValidationResult.Accepted>(await new OidcAuthorizationRequestValidator(repository.Object, Policy()).ValidateAsync(parameters, TestContext.Current.CancellationToken));
        Assert.IsType<OidcAuthorizationValidationResult.LocalRejection>(await new OidcAuthorizationRequestValidator(repository.Object).ValidateAsync(parameters, TestContext.Current.CancellationToken));
        app.RedirectUris.Clear();
        Assert.IsType<OidcAuthorizationValidationResult.LocalRejection>(await new OidcAuthorizationRequestValidator(repository.Object, Policy()).ValidateAsync(parameters, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void RegistrationApplier_RejectsWithoutWriting_AndRetainsIdsOnAcceptedConfiguration()
    {
        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), ClientType = OidcClientType.Confidential, IsActive = true };
        var input = new OidcClientConfigurationInput
        {
            AllowAuthorizationCode = true, AllowedScopes = ["openid"], AudienceMode = "PerApplication",
            RedirectUris = ["http://10.20.30.40/callback"], PostLogoutRedirectUris = ["http://10.20.30.40/logout"]
        };
        Assert.Throws<OidcClientConfigurationException>(() => OidcClientConfigurationApplier.Apply(app, input, false));
        Assert.False(app.AllowAuthorizationCode);
        Assert.Empty(app.RedirectUris);
        var change = OidcClientConfigurationApplier.Apply(app, input, false, Policy());
        var ids = app.RedirectUris.Select(x => x.Id).ToArray();
        Assert.Equal(2, change.AddedRegistrations.Count);
        Assert.Empty(OidcClientConfigurationApplier.Apply(app, input, false, Policy()).AddedRegistrations);
        Assert.Equal(ids, app.RedirectUris.Select(x => x.Id));
        Assert.Throws<OidcClientConfigurationException>(() => OidcClientConfigurationApplier.Apply(app, input, false));
        Assert.Equal(ids, app.RedirectUris.Select(x => x.Id));
        input.PostLogoutRedirectUris = [];
        var cleanup = OidcClientConfigurationApplier.Apply(app, input, false,
            OidcRedirectUriPolicy.Default.ForRegistrationRemoval(input.RedirectUris));
        Assert.Single(cleanup.RemovedRegistrations);
        Assert.Single(app.RedirectUris);
        Assert.False(OidcRedirectUriPolicy.Default.Allows(app.RedirectUris.Single().CanonicalUri));
    }

    private static OidcRedirectUriPolicy Policy() => new(false, ["http://10.20.30.40:80", "http://[fd00::1]:8080"]);
}
