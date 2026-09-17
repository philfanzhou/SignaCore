using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Host.Http;
using Xunit;

namespace SignaCore.Tests.Domain;

/// <summary>
/// The <c>EV-02</c> revalidation primitive: <see cref="OidcContinuationRevalidation.BuildParameters"/>
/// rebuilds exactly the eight single-value parameters a validated continuation was created from,
/// the real <see cref="OidcAuthorizationRequestValidator"/> accepts the rebuilt request of an
/// unchanged registration, and the shared <see cref="OidcAuthorizationRedirect.BuildError"/>
/// reproduces the authorize endpoint's original redirect construction byte for byte.
/// </summary>
public sealed class OidcContinuationRevalidationTests
{
    private const string ClientId = "revalidation-client";
    private const string RedirectUri = "https://bff.revalidation.test/callback";
    private const string Scope = "openid profile";
    private const string State = "revalidation-state-0123456789abcdef";
    private const string Nonce = "revalidation-nonce-0123456789abcdef";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string Issuer = "https://issuer.example";

    [Fact]
    public void BuildParameters_CarriesExactlyTheEightSnapshotParameters()
    {
        var continuation = CreateContinuation();

        var parameters = OidcContinuationRevalidation.BuildParameters(continuation, ClientId);

        Assert.Equal(8, new[]
        {
            "response_type", "client_id", "redirect_uri", "scope",
            "state", "nonce", "code_challenge", "code_challenge_method"
        }.Count(name => parameters.Count(name) == 1));
        Assert.Equal("code", parameters.Single("response_type"));
        Assert.Equal(ClientId, parameters.Single("client_id"));
        Assert.Equal(RedirectUri, parameters.Single("redirect_uri"));
        Assert.Equal(Scope, parameters.Single("scope"));
        Assert.Equal(State, parameters.Single("state"));
        Assert.Equal(Nonce, parameters.Single("nonce"));
        Assert.Equal(Challenge, parameters.Single("code_challenge"));
        Assert.Equal("S256", parameters.Single("code_challenge_method"));
    }

    [Fact]
    public async Task TheRealValidator_AcceptsTheRebuiltSnapshotOfAnUnchangedRegistration()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var database = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection).Options);
        await database.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);

        var applicationId = Guid.NewGuid();
        database.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = applicationId,
            AppId = ClientId,
            AppSecretHash = "hash",
            AppName = "Revalidation Client",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = "openid profile",
            AllowRefreshToken = false,
            RedirectUris =
            [
                new AppRedirectUriEntity
                {
                    Id = Guid.NewGuid(),
                    AppRegistrationId = applicationId,
                    Kind = RedirectUriKind.Redirect,
                    CanonicalUri = RedirectUri
                }
            ]
        });
        await database.SaveChangesAsync(TestContext.Current.CancellationToken);
        database.ChangeTracker.Clear();

        var validator = new OidcAuthorizationRequestValidator(
            new AppRegistrationRepository(database));
        var continuation = CreateContinuation(applicationId);

        var result = await validator.ValidateAsync(
            OidcContinuationRevalidation.BuildParameters(continuation, ClientId),
            TestContext.Current.CancellationToken);

        var accepted = Assert.IsType<OidcAuthorizationValidationResult.Accepted>(result);
        Assert.Equal(applicationId, accepted.ApplicationId);
        Assert.Equal(RedirectUri, accepted.RegisteredRedirectUri);
        Assert.Equal(State, accepted.State);
        Assert.Equal(Nonce, accepted.Nonce);
        Assert.Equal(Challenge, accepted.CodeChallenge);
    }

    [Theory]
    [InlineData("https://client.example.com/callback", "state-value", "invalid_request",
        "The request is invalid.")]
    [InlineData("https://client.example.com/callback", null, "invalid_request",
        "The request is invalid.")]
    [InlineData("https://client.example.com/cb?tenant=blue", "state-value", "access_denied",
        "The user cancelled the authorization request.")]
    [InlineData("https://client.example.com/cb?tenant=blue", null, "access_denied",
        "The user cancelled the authorization request.")]
    public void BuildError_MatchesTheAuthorizeEndpointConstructionByteForByte(
        string registeredRedirectUri,
        string? state,
        string error,
        string errorDescription)
    {
        // The reference implementation is the authorize endpoint's original private construction,
        // inlined here verbatim so the extraction cannot change a single byte.
        var separator = registeredRedirectUri.Contains('?', StringComparison.Ordinal)
            ? '&'
            : '?';
        var reference = new StringBuilder(registeredRedirectUri);
        reference.Append(separator);
        Append(reference, "error", error, first: true);
        Append(reference, "error_description", errorDescription, first: false);
        if (state is not null)
        {
            Append(reference, "state", state, first: false);
        }

        Append(reference, "iss", Issuer, first: false);

        Assert.Equal(
            reference.ToString(),
            OidcAuthorizationRedirect.BuildError(
                registeredRedirectUri, error, errorDescription, state, Issuer));

        static void Append(StringBuilder builder, string name, string value, bool first)
        {
            if (!first)
            {
                builder.Append('&');
            }

            builder.Append(name).Append('=').Append(Uri.EscapeDataString(value));
        }
    }

    private static AuthorizationRequestEntity CreateContinuation(Guid? applicationId = null)
    {
        return new AuthorizationRequestEntity
        {
            Id = Guid.NewGuid(),
            HandleDigest = LoginHandleDigest.Compute("revalidation-handle-0123456789abcde"),
            AppRegistrationId = applicationId ?? Guid.NewGuid(),
            RedirectUri = RedirectUri,
            Scope = Scope,
            State = State,
            Nonce = Nonce,
            CodeChallenge = Challenge,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes)
        };
    }
}
