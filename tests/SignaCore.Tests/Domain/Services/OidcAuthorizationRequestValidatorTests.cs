using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

/// <summary>
/// Field-level and ordering contract of <c>GET /oauth2/authorize</c> validation. The HTTP shape of
/// each outcome is asserted separately by the endpoint contract tests; this suite proves which
/// outcome a given request produces and, above all, that no unverified redirect destination can be
/// reached before the client and the exact registration have both been proved.
/// </summary>
public class OidcAuthorizationRequestValidatorTests
{
    private const string ClientId = "interactive-bff";
    private const string RegisteredUri = "https://bff.example.test/callback";
    private const string ValidState = "state-0123456789012345";
    private const string ValidNonce = "nonce-0123456789012345";
    private const string ValidChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [Fact]
    public async Task DuplicateClientId_IsRejectedLocally()
    {
        var result = await ValidateAsync(Valid().With("client_id", ClientId, ClientId));

        AssertLocal(result, OidcAuthorizationLocalReasons.ClientParameterCardinality);
    }

    [Fact]
    public async Task DuplicateRedirectUri_IsRejectedLocally()
    {
        var result = await ValidateAsync(Valid().With("redirect_uri", RegisteredUri, RegisteredUri));

        AssertLocal(result, OidcAuthorizationLocalReasons.RedirectParameterCardinality);
    }

    /// <summary>Identical duplicates are still duplicates: no implicit first- or last-wins choice.</summary>
    [Fact]
    public async Task DuplicateClientIdAndRedirectUri_IsRejectedLocallyOnTheClientFirst()
    {
        var result = await ValidateAsync(Valid()
            .With("client_id", ClientId, ClientId)
            .With("redirect_uri", RegisteredUri, RegisteredUri));

        AssertLocal(result, OidcAuthorizationLocalReasons.ClientParameterCardinality);
    }

    [Fact]
    public async Task MissingClientId_IsRejectedLocally()
    {
        var result = await ValidateAsync(Valid().Without("client_id"));

        AssertLocal(result, OidcAuthorizationLocalReasons.ClientIdShape);
    }

    [Fact]
    public async Task OverlongClientId_IsRejectedBeforeAnyLookup()
    {
        var repository = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);

        var result = await new OidcAuthorizationRequestValidator(repository.Object)
            .ValidateAsync(Valid().With("client_id", new string('a', 101)).Build(), TestContext.Current.CancellationToken);

        AssertLocal(result, OidcAuthorizationLocalReasons.ClientIdShape);
        repository.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task UnknownClient_IsRejectedLocally()
    {
        var result = await ValidateAsync(Valid(), application: null);

        AssertLocal(result, OidcAuthorizationLocalReasons.ClientUnknown);
    }

    [Fact]
    public async Task InactiveClient_IsRejectedLocally()
    {
        var application = InteractiveApplication();
        application.IsActive = false;

        AssertLocal(await ValidateAsync(Valid(), application), OidcAuthorizationLocalReasons.ClientInactive);
    }

    [Fact]
    public async Task ClientWithoutAuthorizationCode_IsRejectedLocally()
    {
        var application = InteractiveApplication();
        application.AllowAuthorizationCode = false;

        AssertLocal(await ValidateAsync(Valid(), application), OidcAuthorizationLocalReasons.ClientNotInteractive);
    }

    [Fact]
    public async Task PublicClient_IsRejectedLocally()
    {
        var application = InteractiveApplication();
        application.ClientType = OidcClientType.Public;

        AssertLocal(await ValidateAsync(Valid(), application), OidcAuthorizationLocalReasons.ClientNotInteractive);
    }

    [Fact]
    public async Task SharedAudienceClient_IsRejectedLocally()
    {
        var application = InteractiveApplication();
        application.AudienceMode = AudienceMode.Shared;

        AssertLocal(await ValidateAsync(Valid(), application), OidcAuthorizationLocalReasons.ClientNotInteractive);
    }

    /// <summary>
    /// The request is never normalized, so every one of these differs from the registered canonical
    /// string and none of them may become a destination.
    /// </summary>
    [Theory]
    [InlineData("https://bff.example.test/callback/")]
    [InlineData("https://bff.example.test/Callback")]
    [InlineData("https://bff.example.test:443/callback")]
    [InlineData("https://bff.example.test/callback?extra=1")]
    [InlineData("https://bff.example.test.attacker.test/callback")]
    [InlineData("HTTPS://bff.example.test/callback")]
    public async Task RedirectUriThatIsNotTheRegisteredString_IsRejectedLocally(string submitted)
    {
        var result = await ValidateAsync(Valid().With("redirect_uri", submitted));

        AssertLocal(result, OidcAuthorizationLocalReasons.RedirectUriUnmatched);
    }

    [Fact]
    public async Task MissingRedirectUri_IsRejectedLocally()
    {
        var result = await ValidateAsync(Valid().Without("redirect_uri"));

        AssertLocal(result, OidcAuthorizationLocalReasons.RedirectUriShape);
    }

    [Fact]
    public async Task OverlongRedirectUri_IsRejectedLocally()
    {
        var result = await ValidateAsync(Valid()
            .With("redirect_uri", "https://bff.example.test/" + new string('a', 500)));

        AssertLocal(result, OidcAuthorizationLocalReasons.RedirectUriShape);
    }

    /// <summary>A post-logout registration is a different set and never satisfies a redirect.</summary>
    [Fact]
    public async Task PostLogoutRegistration_DoesNotSatisfyTheRedirectUri()
    {
        var application = InteractiveApplication();
        application.RedirectUris =
        [
            new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                Kind = RedirectUriKind.PostLogout,
                CanonicalUri = RegisteredUri
            }
        ];

        AssertLocal(await ValidateAsync(Valid(), application), OidcAuthorizationLocalReasons.RedirectUriUnmatched);
    }

    /// <summary>
    /// The ordering proof. Both requests are invalid twice over, and in both the stage that decides
    /// redirect trust must win, so neither can produce a redirect carrying the later error.
    /// </summary>
    [Fact]
    public async Task UnmatchedRedirectUriWithInvalidScope_IsLocalRatherThanARedirectedInvalidScope()
    {
        var result = await ValidateAsync(Valid()
            .With("redirect_uri", "https://attacker.test/callback")
            .With("scope", "openid unknown_scope"));

        AssertLocal(result, OidcAuthorizationLocalReasons.RedirectUriUnmatched);
    }

    [Fact]
    public async Task UnknownClientWithInvalidState_IsLocalRatherThanARedirectedInvalidRequest()
    {
        var result = await ValidateAsync(Valid().With("state", "short"), application: null);

        AssertLocal(result, OidcAuthorizationLocalReasons.ClientUnknown);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("token")]
    [InlineData("code id_token")]
    [InlineData("CODE")]
    public async Task InvalidResponseType_IsARedirectedUnsupportedResponseType(string? responseType)
    {
        var builder = responseType is null
            ? Valid().Without("response_type")
            : Valid().With("response_type", responseType);

        var result = await ValidateAsync(builder);

        var redirect = AssertRedirect(result, OAuthErrorCodes.UnsupportedResponseType);
        Assert.Equal(ValidState, redirect.State);
    }

    [Theory]
    [InlineData("profile")]
    [InlineData("openid unknown_scope")]
    [InlineData("openid openid")]
    [InlineData("openid  profile")]
    [InlineData("")]
    public async Task InvalidScope_IsARedirectedInvalidScope(string scope)
    {
        var result = await ValidateAsync(Valid().With("scope", scope));

        AssertRedirect(result, OAuthErrorCodes.InvalidScope);
    }

    [Fact]
    public async Task OverlongScope_IsARedirectedInvalidScope()
    {
        var result = await ValidateAsync(Valid().With("scope", "openid " + new string('a', 200)));

        AssertRedirect(result, OAuthErrorCodes.InvalidScope);
    }

    /// <summary>
    /// The scope is inside the supported set but outside this client's current allow list, which is
    /// rejected rather than silently narrowed to what the client may have.
    /// </summary>
    [Fact]
    public async Task ScopeOutsideTheClientAllowList_IsARedirectedInvalidScope()
    {
        var application = InteractiveApplication();
        application.AllowedScopes = "openid";

        var result = await ValidateAsync(Valid().With("scope", "openid profile"), application);

        AssertRedirect(result, OAuthErrorCodes.InvalidScope);
    }

    [Fact]
    public async Task OfflineAccessWithoutRefreshEnabled_IsARedirectedInvalidScope()
    {
        var application = InteractiveApplication();
        application.AllowedScopes = "openid profile offline_access";
        application.AllowRefreshToken = false;

        var result = await ValidateAsync(Valid().With("scope", "openid offline_access"), application);

        AssertRedirect(result, OAuthErrorCodes.InvalidScope);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("too-short-for-state")]
    [InlineData("state with spaces and more text")]
    [InlineData("state+plus+is+outside+the+set")]
    public async Task InvalidState_IsARedirectedInvalidRequestWithoutAnyStateEcho(string? state)
    {
        var builder = state is null ? Valid().Without("state") : Valid().With("state", state);

        var result = await ValidateAsync(builder);

        var redirect = AssertRedirect(result, OAuthErrorCodes.InvalidRequest);
        Assert.Null(redirect.State);
    }

    [Fact]
    public async Task OverlongState_IsARedirectedInvalidRequest()
    {
        var result = await ValidateAsync(Valid().With("state", new string('a', 129)));

        var redirect = AssertRedirect(result, OAuthErrorCodes.InvalidRequest);
        Assert.Null(redirect.State);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("too-short")]
    [InlineData("nonce!0123456789012345")]
    public async Task InvalidNonce_IsARedirectedInvalidRequest(string? nonce)
    {
        var builder = nonce is null ? Valid().Without("nonce") : Valid().With("nonce", nonce);

        AssertRedirect(await ValidateAsync(builder), OAuthErrorCodes.InvalidRequest);
    }

    /// <summary>
    /// The challenge alphabet is narrower than the RFC 7636 ABNF: <c>.</c> and <c>~</c> are legal
    /// there but cannot appear in unpadded base64url, so a challenge containing them could never be
    /// satisfied by any verifier.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("tooshort")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cMx")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c.")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c~")]
    public async Task InvalidCodeChallenge_IsARedirectedInvalidRequest(string? challenge)
    {
        var builder = challenge is null
            ? Valid().Without("code_challenge")
            : Valid().With("code_challenge", challenge);

        AssertRedirect(await ValidateAsync(builder), OAuthErrorCodes.InvalidRequest);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("plain")]
    [InlineData("s256")]
    [InlineData("S512")]
    public async Task InvalidCodeChallengeMethod_IsARedirectedInvalidRequest(string? method)
    {
        var builder = method is null
            ? Valid().Without("code_challenge_method")
            : Valid().With("code_challenge_method", method);

        AssertRedirect(await ValidateAsync(builder), OAuthErrorCodes.InvalidRequest);
    }

    [Theory]
    [InlineData("prompt", "login")]
    [InlineData("max_age", "0")]
    [InlineData("acr_values", "urn:example")]
    [InlineData("response_mode", "form_post")]
    public async Task RejectedField_IsARedirectedInvalidRequest(string name, string value)
    {
        var result = await ValidateAsync(Valid().With(name, value));

        var redirect = AssertRedirect(result, OAuthErrorCodes.InvalidRequest);
        Assert.Equal(OidcAuthorizationErrorDescriptions.UnsupportedParameter, redirect.ErrorDescription);
    }

    [Theory]
    [InlineData("request", OAuthErrorCodes.RequestNotSupported)]
    [InlineData("request_uri", OAuthErrorCodes.RequestUriNotSupported)]
    [InlineData("registration", OAuthErrorCodes.RegistrationNotSupported)]
    public async Task NamedUnsupportedField_UsesItsOwnError(string name, string expectedError)
    {
        AssertRedirect(await ValidateAsync(Valid().With(name, "value")), expectedError);
    }

    [Fact]
    public async Task UnknownField_IsIgnored()
    {
        var result = await ValidateAsync(Valid().With("ui_locales", "en-US").With("unknown", "x"));

        Assert.IsType<OidcAuthorizationValidationResult.Accepted>(result);
    }

    [Fact]
    public async Task DuplicateSupportedField_IsARedirectedInvalidRequest()
    {
        var result = await ValidateAsync(Valid().With("scope", "openid", "openid"));

        var redirect = AssertRedirect(result, OAuthErrorCodes.InvalidRequest);
        Assert.Equal(OidcAuthorizationErrorDescriptions.DuplicateParameter, redirect.ErrorDescription);
    }

    [Fact]
    public async Task DuplicateRejectedField_IsARedirectedInvalidRequestBeforeItsValueIsRead()
    {
        var result = await ValidateAsync(Valid().With("request_uri", "a", "b"));

        var redirect = AssertRedirect(result, OAuthErrorCodes.InvalidRequest);
        Assert.Equal(OidcAuthorizationErrorDescriptions.DuplicateParameter, redirect.ErrorDescription);
    }

    [Theory]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("Mixed.Case~With-All_Unreserved.0123456789")]
    [InlineData("~.-_aaaaaaaaaaaaaaaaaaa")]
    public async Task ValidState_IsEchoedByteForByte(string state)
    {
        var result = await ValidateAsync(Valid().With("state", state).With("scope", "unsupported"));

        var redirect = AssertRedirect(result, OAuthErrorCodes.InvalidScope);
        Assert.Equal(state, redirect.State);
    }

    [Fact]
    public async Task ValidRequest_IsAcceptedWithCanonicalScope()
    {
        var application = InteractiveApplication();
        application.AllowedScopes = "openid profile offline_access";
        application.AllowRefreshToken = true;

        var result = await ValidateAsync(
            Valid().With("scope", "offline_access openid profile"),
            application);

        var accepted = Assert.IsType<OidcAuthorizationValidationResult.Accepted>(result);
        Assert.Equal("openid profile offline_access", accepted.CanonicalScope);
        Assert.Equal(ClientId, accepted.ClientId);
        Assert.Equal(RegisteredUri, accepted.RegisteredRedirectUri);
        Assert.Equal(ValidState, accepted.State);
        Assert.Equal(ValidNonce, accepted.Nonce);
        Assert.Equal(ValidChallenge, accepted.CodeChallenge);
    }

    /// <summary>
    /// The result carries the registered canonical string rather than the submitted bytes, so no
    /// request input is ever concatenated into a destination even when the two are equal.
    /// </summary>
    [Fact]
    public async Task RedirectRejection_CarriesTheRegisteredStringNotTheSubmittedOne()
    {
        var result = await ValidateAsync(Valid().With("response_type", "token"));

        var redirect = AssertRedirect(result, OAuthErrorCodes.UnsupportedResponseType);
        Assert.Same(
            InteractiveApplicationRegisteredUriInstance,
            redirect.RegisteredRedirectUri);
    }

    private static readonly string InteractiveApplicationRegisteredUriInstance =
        string.Concat("https://bff.example.test", "/callback");

    private static void AssertLocal(OidcAuthorizationValidationResult result, string expectedReason)
    {
        var local = Assert.IsType<OidcAuthorizationValidationResult.LocalRejection>(result);
        Assert.Equal(expectedReason, local.Reason);
    }

    private static OidcAuthorizationValidationResult.RedirectRejection AssertRedirect(
        OidcAuthorizationValidationResult result,
        string expectedError)
    {
        var redirect = Assert.IsType<OidcAuthorizationValidationResult.RedirectRejection>(result);
        Assert.Equal(expectedError, redirect.Error);
        Assert.Equal(RegisteredUri, redirect.RegisteredRedirectUri);
        return redirect;
    }

    private static Task<OidcAuthorizationValidationResult> ValidateAsync(ParameterBuilder builder)
    {
        return ValidateAsync(builder, InteractiveApplication());
    }

    private static async Task<OidcAuthorizationValidationResult> ValidateAsync(
        ParameterBuilder builder,
        AppRegistrationEntity? application)
    {
        var repository = new Mock<IAppRegistrationRepository>();
        repository
            .Setup(r => r.GetByAppIdWithOidcConfigurationAsync(
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(application);

        return await new OidcAuthorizationRequestValidator(repository.Object)
            .ValidateAsync(builder.Build(), TestContext.Current.CancellationToken);
    }

    private static AppRegistrationEntity InteractiveApplication()
    {
        return new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = ClientId,
            IsActive = true,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = "openid profile",
            AllowRefreshToken = false,
            AudienceMode = AudienceMode.PerApplication,
            RedirectUris =
            [
                new AppRedirectUriEntity
                {
                    Id = Guid.NewGuid(),
                    Kind = RedirectUriKind.Redirect,
                    CanonicalUri = InteractiveApplicationRegisteredUriInstance
                },
                new AppRedirectUriEntity
                {
                    Id = Guid.NewGuid(),
                    Kind = RedirectUriKind.PostLogout,
                    CanonicalUri = "https://bff.example.test/signed-out"
                }
            ]
        };
    }

    private static ParameterBuilder Valid()
    {
        return new ParameterBuilder()
            .With("response_type", "code")
            .With("client_id", ClientId)
            .With("redirect_uri", RegisteredUri)
            .With("scope", "openid profile")
            .With("state", ValidState)
            .With("nonce", ValidNonce)
            .With("code_challenge", ValidChallenge)
            .With("code_challenge_method", "S256");
    }

    private sealed class ParameterBuilder
    {
        private readonly Dictionary<string, IReadOnlyList<string>> _values = new(StringComparer.Ordinal);

        public ParameterBuilder With(string name, params string[] values)
        {
            _values[name] = values;
            return this;
        }

        public ParameterBuilder Without(string name)
        {
            _values.Remove(name);
            return this;
        }

        public OidcAuthorizationParameters Build()
        {
            return new OidcAuthorizationParameters(_values);
        }
    }
}
