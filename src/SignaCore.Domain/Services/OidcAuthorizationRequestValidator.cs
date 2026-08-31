using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Validators;

namespace SignaCore.Domain.Services;

public interface IOidcAuthorizationRequestValidator
{
    Task<OidcAuthorizationValidationResult> ValidateAsync(
        OidcAuthorizationParameters parameters,
        CancellationToken cancellationToken);
}

/// <summary>
/// Validates one <c>GET /oauth2/authorize</c> request and decides whether a protocol error may be
/// redirected at all.
/// <para>
/// The whole staged order lives here rather than being split across the transport, because the
/// security property is the order itself: a submitted <c>redirect_uri</c> is data until the current
/// client and the exact registration have both been proved, and any code path that could reorder
/// those checks would turn this endpoint into an open redirector. The stages are the canonical
/// ordering paragraph after <c>IN-15</c>:
/// </para>
/// <list type="number">
/// <item>client and redirect parameter cardinality, then <c>client_id</c> shape;</item>
/// <item>current application lookup and interactive capability;</item>
/// <item>ordinal exact match against a registered canonical redirect URI;</item>
/// <item>remaining parameter cardinality, then response type, rejected fields, state, scope,
/// nonce, and the S256 fields.</item>
/// </list>
/// <para>
/// Stage 5 of that paragraph — current identity session and account — is deliberately absent; it
/// belongs to the orchestration slice that also creates the login continuation and the code.
/// </para>
/// </summary>
public sealed class OidcAuthorizationRequestValidator : IOidcAuthorizationRequestValidator
{
    /// <summary>Parameters whose repetition is an error, checked before any of them is read.</summary>
    private static readonly string[] RemainingCountedParameters =
    [
        ResponseType,
        Scope,
        State,
        Nonce,
        CodeChallenge,
        CodeChallengeMethod,
        Prompt,
        MaxAge,
        AcrValues,
        ResponseMode,
        Request,
        RequestUri,
        Registration
    ];

    private const string ClientId = "client_id";
    private const string RedirectUri = "redirect_uri";
    private const string ResponseType = "response_type";
    private const string Scope = "scope";
    private const string State = "state";
    private const string Nonce = "nonce";
    private const string CodeChallenge = "code_challenge";
    private const string CodeChallengeMethod = "code_challenge_method";
    private const string Prompt = "prompt";
    private const string MaxAge = "max_age";
    private const string AcrValues = "acr_values";
    private const string ResponseMode = "response_mode";
    private const string Request = "request";
    private const string RequestUri = "request_uri";
    private const string Registration = "registration";

    private const string ResponseTypeCode = "code";
    private const string CodeChallengeMethodS256 = "S256";

    private const int MinOpaqueValueLength = 22;
    private const int MaxOpaqueValueLength = 128;
    private const int CodeChallengeLength = 43;

    private readonly IAppRegistrationRepository _appRegistrationRepository;

    public OidcAuthorizationRequestValidator(IAppRegistrationRepository appRegistrationRepository)
    {
        _appRegistrationRepository = appRegistrationRepository;
    }

    public async Task<OidcAuthorizationValidationResult> ValidateAsync(
        OidcAuthorizationParameters parameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        // ---- Stage 1: cardinality and shape of the two values that decide redirect trust ----
        if (parameters.Count(ClientId) > 1)
        {
            return Local(OidcAuthorizationLocalReasons.ClientParameterCardinality);
        }

        if (parameters.Count(RedirectUri) > 1)
        {
            return Local(OidcAuthorizationLocalReasons.RedirectParameterCardinality);
        }

        var clientId = parameters.Single(ClientId);
        if (clientId is null || !IsValidClientId(clientId))
        {
            return Local(OidcAuthorizationLocalReasons.ClientIdShape);
        }

        // ---- Stage 2: current application ----
        var application = await _appRegistrationRepository
            .GetByAppIdWithOidcConfigurationAsync(clientId, cancellationToken);
        if (application is null)
        {
            return Local(OidcAuthorizationLocalReasons.ClientUnknown);
        }

        if (!application.IsActive)
        {
            return Local(OidcAuthorizationLocalReasons.ClientInactive);
        }

        // The three interactive preconditions are the same ones registration enforces (PS-21). They
        // are rechecked here so a row written before that policy existed, or by a future path that
        // bypasses the validator, still fails closed.
        if (!application.AllowAuthorizationCode
            || application.ClientType != OidcClientType.Confidential
            || application.AudienceMode != AudienceMode.PerApplication)
        {
            return Local(OidcAuthorizationLocalReasons.ClientNotInteractive);
        }

        // ---- Stage 3: exact registered redirect URI ----
        var submittedRedirectUri = parameters.Single(RedirectUri);
        if (!IsValidRedirectUriShape(submittedRedirectUri))
        {
            return Local(OidcAuthorizationLocalReasons.RedirectUriShape);
        }

        // The request value is never normalized. The comparison value is the canonical string an
        // administrator registered, so equivalence is decided by that registration and not by a URI
        // library's idea of what two URIs mean.
        var registeredRedirectUri = application.RedirectUris
            .Where(uri => uri.Kind == RedirectUriKind.Redirect)
            .Select(uri => uri.CanonicalUri)
            .FirstOrDefault(uri => string.Equals(uri, submittedRedirectUri, StringComparison.Ordinal));
        if (registeredRedirectUri is null)
        {
            return Local(OidcAuthorizationLocalReasons.RedirectUriUnmatched);
        }

        // ---- Stage 4: everything else may now answer through the verified URI ----
        // Capture the echoable state first: a state that is duplicated or malformed is not echoed
        // into any redirect, so no unvalidated request byte can reach the destination URL.
        var echoableState = parameters.Count(State) == 1 && IsValidOpaqueValue(parameters.Single(State))
            ? parameters.Single(State)
            : null;

        OidcAuthorizationValidationResult Redirect(string error, string description) =>
            new OidcAuthorizationValidationResult.RedirectRejection(
                application.AppId,
                application.Id,
                registeredRedirectUri,
                error,
                description,
                echoableState);

        foreach (var name in RemainingCountedParameters)
        {
            if (parameters.Count(name) > 1)
            {
                return Redirect(
                    OAuthErrorCodes.InvalidRequest,
                    OidcAuthorizationErrorDescriptions.DuplicateParameter);
            }
        }

        if (!string.Equals(parameters.Single(ResponseType), ResponseTypeCode, StringComparison.Ordinal))
        {
            return Redirect(
                OAuthErrorCodes.UnsupportedResponseType,
                OidcAuthorizationErrorDescriptions.UnsupportedResponseType);
        }

        if (parameters.Contains(Prompt)
            || parameters.Contains(MaxAge)
            || parameters.Contains(AcrValues)
            || parameters.Contains(ResponseMode))
        {
            return Redirect(
                OAuthErrorCodes.InvalidRequest,
                OidcAuthorizationErrorDescriptions.UnsupportedParameter);
        }

        if (parameters.Contains(Request))
        {
            return Redirect(
                OAuthErrorCodes.RequestNotSupported,
                OidcAuthorizationErrorDescriptions.RequestObjectNotSupported);
        }

        if (parameters.Contains(RequestUri))
        {
            return Redirect(
                OAuthErrorCodes.RequestUriNotSupported,
                OidcAuthorizationErrorDescriptions.RequestUriNotSupported);
        }

        if (parameters.Contains(Registration))
        {
            return Redirect(
                OAuthErrorCodes.RegistrationNotSupported,
                OidcAuthorizationErrorDescriptions.RegistrationNotSupported);
        }

        if (echoableState is null)
        {
            return Redirect(
                OAuthErrorCodes.InvalidRequest,
                OidcAuthorizationErrorDescriptions.MalformedState);
        }

        if (!OidcScopeValidator.TryValidateRequested(
                parameters.Single(Scope),
                OidcScopeValidator.ParseCanonical(application.AllowedScopes),
                application.AllowRefreshToken,
                out var canonicalScope))
        {
            return Redirect(
                OAuthErrorCodes.InvalidScope,
                OidcAuthorizationErrorDescriptions.InvalidScope);
        }

        var nonce = parameters.Single(Nonce);
        if (!IsValidOpaqueValue(nonce))
        {
            return Redirect(
                OAuthErrorCodes.InvalidRequest,
                OidcAuthorizationErrorDescriptions.MalformedNonce);
        }

        var codeChallenge = parameters.Single(CodeChallenge);
        if (!IsValidCodeChallenge(codeChallenge))
        {
            return Redirect(
                OAuthErrorCodes.InvalidRequest,
                OidcAuthorizationErrorDescriptions.MalformedCodeChallenge);
        }

        if (!string.Equals(
                parameters.Single(CodeChallengeMethod),
                CodeChallengeMethodS256,
                StringComparison.Ordinal))
        {
            return Redirect(
                OAuthErrorCodes.InvalidRequest,
                OidcAuthorizationErrorDescriptions.UnsupportedCodeChallengeMethod);
        }

        return new OidcAuthorizationValidationResult.Accepted(
            application.AppId,
            application.Id,
            registeredRedirectUri,
            canonicalScope,
            echoableState,
            nonce!,
            codeChallenge!);
    }

    private static OidcAuthorizationValidationResult Local(string reason)
    {
        return new OidcAuthorizationValidationResult.LocalRejection(reason);
    }

    /// <summary>
    /// <c>IN-02</c>: bounded both as submitted and after the lookup normalization, so a value that
    /// only grows into range through NFC expansion cannot reach the repository.
    /// </summary>
    private static bool IsValidClientId(string value)
    {
        if (value.Length == 0 || value.Length > IdentityConstants.MaxAppIdLength)
        {
            return false;
        }

        var normalizedLength = IdentityValueNormalizer.Normalize(value).Length;
        return normalizedLength > 0 && normalizedLength <= IdentityConstants.MaxAppIdLength;
    }

    /// <summary>
    /// <c>IN-03</c>: a length and character bound only. The request value is never normalized, so
    /// the actual decision is the ordinal comparison against the registered canonical string.
    /// </summary>
    private static bool IsValidRedirectUriShape(string? value)
    {
        return value is not null
            && value.Length > 0
            && value.Length <= IdentityConstants.MaxOidcRedirectUriLength
            && value.All(character => character > 0x20 && character < 0x7f);
    }

    /// <summary><c>IN-05</c> and <c>IN-06</c>: 22–128 ASCII unreserved characters.</summary>
    private static bool IsValidOpaqueValue(string? value)
    {
        return value is not null
            && value.Length >= MinOpaqueValueLength
            && value.Length <= MaxOpaqueValueLength
            && value.All(IsUnreserved);
    }

    /// <summary>
    /// <c>IN-07</c>: exactly the 43 unpadded base64url characters that
    /// <c>BASE64URL(SHA256(ASCII(code_verifier)))</c> can produce. This is narrower than the RFC
    /// 7636 <c>code-challenge</c> ABNF on purpose: accepting <c>.</c> or <c>~</c> would let a client
    /// register a challenge that no verifier could ever satisfy.
    /// </summary>
    private static bool IsValidCodeChallenge(string? value)
    {
        return value is not null
            && value.Length == CodeChallengeLength
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    }

    private static bool IsUnreserved(char character)
    {
        return char.IsAsciiLetterOrDigit(character) || character is '-' or '.' or '_' or '~';
    }
}
