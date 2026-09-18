using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Services;

/// <summary>
/// The one failure result of the redemption slice: the HTTP status, the RFC 6749 error code, the
/// fixed English description, and the closed-set metric reason the controller never rewrites.
/// </summary>
public sealed class AuthorizationCodeRedemptionOutcome
{
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(AccessToken))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(IdToken))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(Scope))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(false, nameof(ErrorCode))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(false, nameof(ErrorDescription))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(false, nameof(FailureReason))]
    public bool IsSuccess { get; private init; }

    /// <summary>The HTTP status the failure must be answered with; 0 on success.</summary>
    public int Status { get; private init; }

    public string? ErrorCode { get; private init; }

    public string? ErrorDescription { get; private init; }

    /// <summary>The closed metric reason: invalid_request, unauthorized_client, invalid_grant, replay, server_error.</summary>
    public string? FailureReason { get; private init; }

    public string? AccessToken { get; private init; }

    /// <summary>The ID token (<c>PS-12</c>) of the same committed redemption; the canonical scope always contains <c>openid</c>.</summary>
    public string? IdToken { get; private init; }

    /// <summary>
    /// The plaintext interactive refresh token of the family root committed in the same
    /// redemption (<c>EV-21</c>/<c>PS-14</c>), present only when the code carried
    /// <c>offline_access</c>; returned exactly once and never persisted.
    /// </summary>
    public string? RefreshToken { get; private init; }

    public long ExpiresIn { get; private init; }

    /// <summary>The code's canonical scope snapshot, echoed byte for byte in the response.</summary>
    public string? Scope { get; private init; }

    public static AuthorizationCodeRedemptionOutcome Success(
        string accessToken,
        string idToken,
        long expiresIn,
        string scope,
        string? refreshToken = null) => new()
    {
        IsSuccess = true,
        AccessToken = accessToken,
        IdToken = idToken,
        RefreshToken = refreshToken,
        ExpiresIn = expiresIn,
        Scope = scope
    };

    public static AuthorizationCodeRedemptionOutcome Failure(
        int status,
        string errorCode,
        string errorDescription,
        string failureReason) => new()
    {
        IsSuccess = false,
        Status = status,
        ErrorCode = errorCode,
        ErrorDescription = errorDescription,
        FailureReason = failureReason
    };
}

/// <summary>
/// The internal <c>authorization_code</c> redemption of the interactive Authorization Code flow
/// (<c>AC-06</c>/<c>AC-07</c>): an authenticated confidential BFF exchanges one code plus its PKCE
/// verifier for an application-scoped interactive access token (<c>PS-13</c>) and, because the
/// canonical scope always contains <c>openid</c>, an ID token (<c>PS-12</c>) — both signed inside
/// one transaction that also consumes the code and writes the redemption audit (<c>EV-20</c>). A
/// code whose approved scope carries <c>offline_access</c> additionally creates and links the
/// family root in the same unit (<c>EV-21</c>) and returns its plaintext refresh token exactly
/// once. A correctly bound replay of an already consumed code revokes the linked family when the
/// code names one, revokes the linked session, and commits exactly one id-only replay audit
/// (<c>EV-24</c>); every lookup, binding, time, and current-state rejection answers with the
/// single generic <c>invalid_grant</c> and consumes nothing (<c>EV-22</c>/<c>EV-23</c>).
/// </summary>
/// <remarks>
/// Same transaction shape as <see cref="OidcLoginCompletionService"/>: the explicit transaction
/// runs as a whole inside <c>CreateExecutionStrategy()</c> because PostgreSQL enables
/// <c>EnableRetryOnFailure()</c> (<c>PS-22</c>), a replayed unit commits exactly once, and
/// cancellation observed before the commit rolls the whole unit back (<c>EV-18</c>/<c>SC-20</c>).
/// The locks follow the canonical session-then-code order (<c>EV-20</c>). External HTTP — the
/// client callback and the signing-key refresh — happens before the transaction opens, never
/// under a held lock. Rotation, consumption semantics, and reuse handling of the created family
/// belong to the interactive refresh slice (#98): until then the issued refresh token cannot be
/// rotated, and a family revoked here or by a session revocation stays revoked.
/// </remarks>
public sealed class AuthorizationCodeRedemptionService(
    IAuthorizationCodeStore authorizationCodes,
    IIdentitySessionStore identitySessions,
    IAccountRepository accounts,
    IPasswordCredentialRepository passwordCredentials,
    IInteractiveAccessTokenFactory tokenFactory,
    IInteractiveIdTokenFactory idTokenFactory,
    IRefreshTokenFamilyStore refreshFamilies,
    ICallbackService? callbackService,
    IKeyManager keyManager,
    IAuditService auditService,
    AuthMetrics authMetrics,
    IUnitOfWork unitOfWork,
    IdentityDbContext dbContext,
    AdminIdentityOptions adminIdentityOptions,
    ILogger<AuthorizationCodeRedemptionService> logger)
{
    public const string GrantType = "authorization_code";

    private const string RedeemedAuditAction = "oidc.code.redeemed";
    private const string ReplayedAuditAction = "oidc.code.replayed";
    private const string CodeAuditTargetType = "AuthorizationCode";

    // EV-22/EV-23/EV-24 share one description; which check failed is never disclosed.
    private const string InvalidCodeGrantDescription = "The authorization code is invalid.";
    private const string MalformedRequestDescription = "A token request parameter is missing or malformed.";
    private const string ScopeNotAcceptedDescription =
        "The authorization code grant does not accept a scope parameter.";
    private const string UnauthorizedClientDescription =
        "This client is not permitted to redeem authorization codes.";
    private const string ServerErrorDescription =
        "The authorization server could not complete the token request.";

    private const int VerifierMinimumLength = 43;
    private const int VerifierMaximumLength = 128;

    /// <summary>
    /// Runs the whole redemption decision under one caller-captured UTC instant
    /// (<c>PS-22</c>): capability and field structure, digest lookup, binding verification, the
    /// non-authoritative prechecks, the claim enrichment, and the transaction. The caller has
    /// already authenticated the client and rejected the Basic-plus-form credential mix
    /// (<c>IN-20</c>).
    /// </summary>
    /// <exception cref="OperationCanceledException">
    /// The caller's token was cancelled; every write rolled back and no error body was produced
    /// (<c>EV-18</c>).
    /// </exception>
    public async Task<AuthorizationCodeRedemptionOutcome> RedeemAsync(
        AppRegistrationEntity app,
        IFormCollection form,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(form);

        var stopwatch = Stopwatch.StartNew();
        try
        {
            return Complete(stopwatch, await RedeemCoreAsync(
                app, form, clientIp, correlationId, cancellationToken));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // EV-26: signing, persistence, audit, or commit failure — everything rolled back and
            // no token bytes released; the response is the single 500 server_error.
            logger.LogError(ex,
                "Authorization code redemption failed before commit: AppId={AppId}, CorrelationId={CorrelationId}",
                LogValueSanitizer.Sanitize(app.AppId),
                LogValueSanitizer.Sanitize(correlationId));
            return Complete(stopwatch, AuthorizationCodeRedemptionOutcome.Failure(
                StatusCodes.Status500InternalServerError,
                OAuthErrorCodes.ServerError,
                ServerErrorDescription,
                "server_error"));
        }
    }

    private async Task<AuthorizationCodeRedemptionOutcome> RedeemCoreAsync(
        AppRegistrationEntity app,
        IFormCollection form,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        // EV-10/PS-21: the capability decision precedes every code lookup.
        if (!app.AllowAuthorizationCode
            || app.ClientType != OidcClientType.Confidential
            || app.AudienceMode != AudienceMode.PerApplication)
        {
            return AuthorizationCodeRedemptionOutcome.Failure(
                StatusCodes.Status400BadRequest,
                OAuthErrorCodes.UnauthorizedClient,
                UnauthorizedClientDescription,
                "unauthorized_client");
        }

        // IN-22–IN-25: exactly one value per admitted field, no scope field at all, and the fixed
        // shapes. Unknown fields are ignored.
        if (!TryReadSingleFormValue(form, "code", out var code)
            || !TryReadSingleFormValue(form, "redirect_uri", out var redirectUri)
            || !TryReadSingleFormValue(form, "code_verifier", out var codeVerifier))
        {
            return AuthorizationCodeRedemptionOutcome.Failure(
                StatusCodes.Status400BadRequest,
                OAuthErrorCodes.InvalidRequest,
                MalformedRequestDescription,
                "invalid_request");
        }

        if (form.ContainsKey("scope"))
        {
            return AuthorizationCodeRedemptionOutcome.Failure(
                StatusCodes.Status400BadRequest,
                OAuthErrorCodes.InvalidRequest,
                ScopeNotAcceptedDescription,
                "invalid_request");
        }

        if (!IsAuthorizationCodeShape(code)
            || !IsRedirectUriShape(redirectUri)
            || !IsVerifierShape(codeVerifier))
        {
            return AuthorizationCodeRedemptionOutcome.Failure(
                StatusCodes.Status400BadRequest,
                OAuthErrorCodes.InvalidRequest,
                MalformedRequestDescription,
                "invalid_request");
        }

        // One captured instant for every comparison and write of this redemption (PS-22).
        var now = DateTimeOffset.UtcNow;

        // EV-22: a bad shape, a missing digest, and a missing row share the single answer.
        var lookup = await authorizationCodes.FindAsync(code, now, cancellationToken);
        if (lookup.State == AuthorizationCodeState.Missing || lookup.Entity is null)
        {
            return InvalidGrant();
        }

        // EV-23: a failed binding takes no replay side effect, even for a consumed code.
        if (!authorizationCodes.VerifyBinding(lookup.Entity, app.Id, redirectUri, codeVerifier))
        {
            return InvalidGrant();
        }

        if (lookup.State == AuthorizationCodeState.Consumed)
        {
            return await ExecuteReplayTransactionAsync(lookup.Entity, now, clientIp, correlationId, cancellationToken);
        }

        if (lookup.State == AuthorizationCodeState.Expired)
        {
            return InvalidGrant();
        }

        // The non-authoritative prechecks keep the callback HTTP and the key refresh away from
        // redemptions the transaction would reject anyway; every authoritative decision is
        // repeated under the locks below.
        var sessionLookup = await identitySessions.GetAsync(
            lookup.Entity.IdentitySessionId, now, cancellationToken);
        if (sessionLookup.State != IdentitySessionState.Active || sessionLookup.Session is null)
        {
            return InvalidGrant();
        }

        var session = sessionLookup.Session;
        var account = await accounts.GetByIdAsync(lookup.Entity.AccountId, cancellationToken);
        if (account is null || !account.IsActive)
        {
            return InvalidGrant();
        }

        if (FailsApplicationSessionPolicy(app, session, now)
            || !IsScopeStillAllowed(lookup.Entity.Scope, app.AllowedScopes))
        {
            return InvalidGrant();
        }

        // Everything below resolves outside the transaction: external HTTP never runs under a
        // held lock, and the descriptor's values survive the ChangeTracker.Clear() of a retry.
        // One credential read feeds both name sources: the access token's display-name fallback
        // and the ID token's PS-12 name, which is always the bound Password username.
        var passwordUsername = await ResolvePasswordUsernameAsync(account, cancellationToken);
        var displayName = !string.IsNullOrWhiteSpace(account.Nickname)
            ? account.Nickname
            : passwordUsername;
        var enrichment = new List<Claim>();
        if (app.CallbackUrl is not null && callbackService is not null)
        {
            try
            {
                enrichment.AddRange(await callbackService.FetchExternalClaimsAsync(
                    app.CallbackUrl, account.Id.ToString(), cancellationToken));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex,
                    "Callback request failed, continuing with basic claims: AppId={AppId}",
                    LogValueSanitizer.Sanitize(app.AppId));
            }
        }

        await InjectBootstrapAdminRoleAsync(account, enrichment, cancellationToken);

        await keyManager.RefreshKeysAsync(cancellationToken);
        var signingKey = keyManager.GetCurrentKey();

        var descriptor = new InteractiveAccessTokenDescriptor(
            account.Id,
            app.AppId,
            session.Id,
            session.AuthMethod,
            lookup.Entity.Scope,
            displayName,
            account.Nickname,
            enrichment);

        return await ExecuteIssuanceTransactionAsync(
            descriptor,
            passwordUsername,
            signingKey,
            lookup.Entity.Id,
            app.Id,
            clientIp,
            correlationId,
            now,
            cancellationToken);
    }

    /// <summary>
    /// The <c>EV-24</c> transaction for a correctly bound consumed code: session lock first, code
    /// lock second, the replay fact from <c>consumed_at</c> alone, the session revocation when the
    /// row still exists, one id-only audit row, and the generic <c>invalid_grant</c> after the
    /// commit.
    /// </summary>
    private async Task<AuthorizationCodeRedemptionOutcome> ExecuteReplayTransactionAsync(
        AuthorizationCodeEntity code,
        DateTimeOffset now,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        var strategy = dbContext.Database.CreateExecutionStrategy();
        var replayCommitted = await strategy.ExecuteAsync(async operationToken =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction = await dbContext.Database
                .BeginTransactionAsync(operationToken);

            // EV-20 lock order. A missing session row is not an error here: the committed
            // consumption alone proves the replay.
            var lockedSession = await identitySessions.LockAsync(code.IdentitySessionId, operationToken);
            var lockedCode = await authorizationCodes.LockAsync(code.Id, operationToken);
            if (lockedCode is null || lockedCode.ConsumedAt is null)
            {
                // Under the locks the committed fact cannot have disappeared; fail closed anyway.
                await transaction.RollbackAsync(operationToken);
                return false;
            }

            await CommitReplayDisposalAsync(
                lockedCode, lockedSession, now, clientIp, correlationId, operationToken);
            await unitOfWork.SaveChangesAsync(operationToken);
            await transaction.CommitAsync(operationToken);
            return true;
        }, cancellationToken);

        if (!replayCommitted)
        {
            return InvalidGrant();
        }

        logger.LogWarning(
            "Authorization code replay detected and the linked session revoked: CodeId={CodeId}",
            code.Id);
        return AuthorizationCodeRedemptionOutcome.Failure(
            StatusCodes.Status400BadRequest,
            OAuthErrorCodes.InvalidGrant,
            InvalidCodeGrantDescription,
            "replay");
    }

    /// <summary>
    /// The <c>EV-20</c> issuance transaction: session lock, code lock, the authoritative rechecks
    /// under the captured instant, both signatures, the conditional consumption, the audit row, and
    /// the commit — after which, and only after which, the token bytes leave this service.
    /// </summary>
    private async Task<AuthorizationCodeRedemptionOutcome> ExecuteIssuanceTransactionAsync(
        InteractiveAccessTokenDescriptor descriptor,
        string? passwordUsername,
        RsaSecurityKey signingKey,
        Guid codeId,
        Guid applicationRowId,
        string? clientIp,
        string? correlationId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var strategy = dbContext.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async operationToken =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction = await dbContext.Database
                .BeginTransactionAsync(operationToken);

            // EV-20 lock order: the loser of a concurrent redemption observes the committed
            // consumption under the locks and runs the replay disposal instead.
            var lockedSession = await identitySessions.LockAsync(descriptor.SessionId, operationToken);
            if (lockedSession is null)
            {
                await transaction.RollbackAsync(operationToken);
                return InvalidGrant();
            }

            var lockedCode = await authorizationCodes.LockAsync(codeId, operationToken);
            if (lockedCode is null)
            {
                await transaction.RollbackAsync(operationToken);
                return InvalidGrant();
            }

            if (lockedCode.ConsumedAt is not null)
            {
                await CommitReplayDisposalAsync(
                    lockedCode, lockedSession, now, clientIp, correlationId, operationToken);
                await unitOfWork.SaveChangesAsync(operationToken);
                await transaction.CommitAsync(operationToken);
                logger.LogWarning(
                    "Authorization code replay detected and the linked session revoked: CodeId={CodeId}",
                    lockedCode.Id);
                return AuthorizationCodeRedemptionOutcome.Failure(
                    StatusCodes.Status400BadRequest,
                    OAuthErrorCodes.InvalidGrant,
                    InvalidCodeGrantDescription,
                    "replay");
            }

            // The authoritative rechecks under the same captured instant: code expiry, session
            // classification, the current application and its session policy, the account, and
            // the current scope allow list (EV-04/05/08/09/10/13).
            var currentApplication = await ReadApplicationAsync(applicationRowId, operationToken);
            if (now >= lockedCode.ExpiresAt
                || IdentitySessionStore.Classify(lockedSession, now) != IdentitySessionState.Active
                || currentApplication is null
                || !currentApplication.IsActive
                || FailsApplicationSessionPolicy(currentApplication, lockedSession, now))
            {
                await transaction.RollbackAsync(operationToken);
                return InvalidGrant();
            }

            if (!currentApplication.AllowAuthorizationCode)
            {
                await transaction.RollbackAsync(operationToken);
                return AuthorizationCodeRedemptionOutcome.Failure(
                    StatusCodes.Status400BadRequest,
                    OAuthErrorCodes.UnauthorizedClient,
                    UnauthorizedClientDescription,
                    "unauthorized_client");
            }

            var lockedAccount = await accounts.GetByIdAsync(descriptor.AccountId, operationToken);
            if (lockedAccount is null || !lockedAccount.IsActive)
            {
                await transaction.RollbackAsync(operationToken);
                return InvalidGrant();
            }

            if (!IsScopeStillAllowed(lockedCode.Scope, currentApplication.AllowedScopes))
            {
                await transaction.RollbackAsync(operationToken);
                return InvalidGrant();
            }

            // EV-11: the current refresh capability is an authoritative in-lock recheck — a code
            // whose approved scope carries offline_access is only redeemable while the application
            // still allows refresh tokens. The code stays unconsumed and no family is written.
            var codeCarriesOfflineAccess = ContainsOfflineAccess(lockedCode.Scope);
            if (codeCarriesOfflineAccess && !currentApplication.AllowRefreshToken)
            {
                await transaction.RollbackAsync(operationToken);
                return InvalidGrant();
            }

            // Both signatures are part of the unit: an oversized or failing construction of either
            // token rolls the consumption back with everything else (EV-26).
            if (tokenFactory.Create(descriptor, signingKey, now)
                is not InteractiveAccessTokenResult.Issued issued)
            {
                await transaction.RollbackAsync(operationToken);
                return AuthorizationCodeRedemptionOutcome.Failure(
                    StatusCodes.Status500InternalServerError,
                    OAuthErrorCodes.ServerError,
                    ServerErrorDescription,
                    "server_error");
            }

            // PS-12: the ID token's nonce and auth_time are byte-for-byte the locked code row's
            // snapshots, never a token-request value, and the profile sources are the locked rows.
            var idDescriptor = new InteractiveIdTokenDescriptor(
                lockedAccount.Id,
                descriptor.ClientId,
                lockedSession.Id,
                lockedSession.AuthMethod,
                lockedCode.Scope,
                lockedCode.Nonce,
                lockedCode.AuthTime,
                passwordUsername,
                lockedAccount.Nickname);
            if (idTokenFactory.Create(idDescriptor, signingKey, now)
                is not InteractiveIdTokenResult.Issued issuedIdToken)
            {
                await transaction.RollbackAsync(operationToken);
                return AuthorizationCodeRedemptionOutcome.Failure(
                    StatusCodes.Status500InternalServerError,
                    OAuthErrorCodes.ServerError,
                    ServerErrorDescription,
                    "server_error");
            }

            // The conditional consumption is required even under the lock: it is the single
            // point the one-redemption invariant is enforced against implementation drift.
            if (!await authorizationCodes.TryConsumeAsync(lockedCode.Id, now, operationToken))
            {
                await transaction.RollbackAsync(operationToken);
                return InvalidGrant();
            }

            // EV-21: with offline_access the family root and the code-to-root link commit in this
            // same unit. The store flushes the staged root so the conditional link write can
            // resolve its restrictive reference; both roll back with everything else on any
            // failure before the commit (EV-26).
            InteractiveRefreshFamilyRootCreation? familyRoot = null;
            if (codeCarriesOfflineAccess)
            {
                familyRoot = await refreshFamilies.CreateRootAsync(
                    new InteractiveRefreshFamilyRootDescriptor(
                        lockedAccount.Id,
                        descriptor.ClientId,
                        lockedSession.Id,
                        lockedCode.Scope,
                        lockedCode.AuthTime),
                    now,
                    operationToken);
                if (!await authorizationCodes.LinkRefreshFamilyAsync(
                        lockedCode.Id, familyRoot.RootId, operationToken))
                {
                    // The conditional consumption just succeeded, so an unlinked row cannot have
                    // disappeared; fail closed on the invariant violation.
                    throw new InvalidOperationException(
                        "The consumed authorization code could not be linked to its refresh family root.");
                }
            }

            await auditService.RecordActionAsync(
                RedeemedAuditAction,
                CodeAuditTargetType,
                lockedCode.Id.ToString("D"),
                actorId: lockedAccount.Id,
                actorName: null,
                description: $"session:{lockedSession.Id}",
                clientIp: clientIp,
                correlationId: correlationId,
                cancellationToken: operationToken);
            await unitOfWork.SaveChangesAsync(operationToken);
            await transaction.CommitAsync(operationToken);

            logger.LogInformation(
                "Authorization code redeemed: AccountId={AccountId}, AppId={AppId}, CodeId={CodeId}",
                lockedAccount.Id,
                LogValueSanitizer.Sanitize(descriptor.ClientId),
                lockedCode.Id);
            return AuthorizationCodeRedemptionOutcome.Success(
                issued.AccessToken,
                issuedIdToken.IdToken,
                IdentityConstants.InteractiveAccessTokenLifetimeSeconds,
                lockedCode.Scope,
                familyRoot?.RefreshToken);
        }, cancellationToken);
    }

    /// <summary>
    /// The shared disposal of one proven replay: the precise family revocation when the code
    /// names one (<c>EV-24</c> — never a guessed sibling), the session revocation when the row
    /// still exists (<c>AlreadyRevoked</c> keeps the first fact), and the staged id-only audit
    /// row. The caller owns the transaction and the commit.
    /// </summary>
    private async Task CommitReplayDisposalAsync(
        AuthorizationCodeEntity lockedCode,
        IdentitySessionEntity? lockedSession,
        DateTimeOffset now,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        // The link names the exact family this code's first redemption created; sibling families
        // of the same session become unusable through the session revocation below, never by
        // direct writes (SC-07/SC-09).
        var familyDescription = "none";
        if (lockedCode.RefreshFamilyId is Guid rootId)
        {
            await refreshFamilies.RevokeFamilyAsync(
                rootId, RefreshFamilyRevocationReason.CodeReplay, cancellationToken);
            familyDescription = rootId.ToString("D");
        }

        if (lockedSession is not null)
        {
            await identitySessions.RevokeAsync(
                lockedSession.Id, IdentitySessionRevocationReason.CodeReplay, now, cancellationToken);
        }

        await auditService.RecordActionAsync(
            ReplayedAuditAction,
            CodeAuditTargetType,
            lockedCode.Id.ToString("D"),
            actorId: lockedCode.AccountId,
            actorName: null,
            description: $"session:{lockedCode.IdentitySessionId};family:{familyDescription}",
            clientIp: clientIp,
            correlationId: correlationId,
            cancellationToken: cancellationToken);
    }

    private async Task<AppRegistrationEntity?> ReadApplicationAsync(
        Guid applicationRowId,
        CancellationToken cancellationToken) =>
        await dbContext.AppRegistrations
            .AsNoTracking()
            .SingleOrDefaultAsync(application => application.Id == applicationRowId, cancellationToken);

    /// <summary>
    /// <c>EV-05</c>: the per-application session max-age, evaluated against the re-read
    /// application inside the transaction and against the authentication-time application in the
    /// prechecks. The session row is never modified for another application's policy.
    /// </summary>
    private static bool FailsApplicationSessionPolicy(
        AppRegistrationEntity application,
        IdentitySessionEntity session,
        DateTimeOffset now) =>
        application.IdentitySessionMaxAgeSeconds is int maxAgeSeconds
        && now >= session.AuthTime.AddSeconds(maxAgeSeconds);

    private static bool IsScopeStillAllowed(string scopeSnapshot, string currentAllowedScopes)
    {
        var allowed = OidcScopeValidator.ParseCanonical(currentAllowedScopes);
        return SplitCanonicalScope(scopeSnapshot).All(allowed.Contains);
    }

    private static bool ContainsOfflineAccess(string scopeSnapshot) =>
        SplitCanonicalScope(scopeSnapshot).Contains(OidcScopeValidator.OfflineAccess);

    private static string[] SplitCanonicalScope(string scopeSnapshot) =>
        scopeSnapshot.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    /// <summary>
    /// The bound Password username of the account, or null when the account has no password
    /// credential. The ID token's <c>PS-12</c> <c>name</c> claim uses exactly this value — a
    /// different source than the access token's display-name resolution.
    /// </summary>
    private async Task<string?> ResolvePasswordUsernameAsync(
        AccountEntity account,
        CancellationToken cancellationToken)
    {
        var credential = await passwordCredentials.GetByAccountIdAsync(account.Id, cancellationToken);
        return credential?.Username;
    }

    /// <summary>
    /// Same rule as the refresh branch of <see cref="TokenIssuanceService"/>: the bootstrap
    /// administrator is resolved from the configured username's password credential, never from
    /// client-controlled input, and the role is appended after the callback claims.
    /// </summary>
    private async Task InjectBootstrapAdminRoleAsync(
        AccountEntity account,
        List<Claim> claims,
        CancellationToken cancellationToken)
    {
        var bootstrapUsername = adminIdentityOptions.Username;
        if (string.IsNullOrWhiteSpace(bootstrapUsername))
        {
            return;
        }

        var bootstrapAccount = await accounts.GetByPasswordCredentialUsernameAsync(
            bootstrapUsername.Trim(), cancellationToken);
        if (bootstrapAccount is null || bootstrapAccount.Id != account.Id)
        {
            return;
        }

        if (claims.Any(claim =>
                claim.Type == IdentityConstants.ClaimRole
                && string.Equals(claim.Value, "admin", StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        claims.Add(new Claim(IdentityConstants.ClaimRole, "admin"));
        logger.LogInformation(
            "Injected bootstrap admin role for account {AccountId}",
            account.Id);
    }

    private AuthorizationCodeRedemptionOutcome InvalidGrant() =>
        AuthorizationCodeRedemptionOutcome.Failure(
            StatusCodes.Status400BadRequest,
            OAuthErrorCodes.InvalidGrant,
            InvalidCodeGrantDescription,
            "invalid_grant");

    private AuthorizationCodeRedemptionOutcome Complete(
        Stopwatch stopwatch,
        AuthorizationCodeRedemptionOutcome outcome)
    {
        stopwatch.Stop();
        if (outcome.IsSuccess)
        {
            authMetrics.RecordLoginSuccess(GrantType);
        }
        else
        {
            authMetrics.RecordLoginFailure(GrantType, outcome.FailureReason!);
        }

        authMetrics.RecordLoginDuration(stopwatch.Elapsed.TotalMilliseconds, GrantType);
        return outcome;
    }

    private static bool TryReadSingleFormValue(
        IFormCollection form,
        string name,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? value)
    {
        if (!form.TryGetValue(name, out var values) || values.Count != 1)
        {
            value = null;
            return false;
        }

        value = values[0] ?? string.Empty;
        return true;
    }

    /// <summary>The <c>IN-22</c> shape: exactly 43 <c>[A-Za-z0-9_-]</c> characters.</summary>
    private static bool IsAuthorizationCodeShape(string? value) =>
        value is not null
        && value.Length == IdentityConstants.AuthorizationCodeLength
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    /// <summary>The <c>IN-23</c> shape: 1–500 printable ASCII characters.</summary>
    private static bool IsRedirectUriShape(string? value) =>
        value is not null
        && value.Length is >= 1 and <= IdentityConstants.MaxOidcRedirectUriLength
        && value.All(character => character is >= ' ' and <= '~');

    /// <summary>The <c>IN-24</c> shape: 43–128 ASCII <c>[A-Za-z0-9._~-]</c>.</summary>
    private static bool IsVerifierShape(string? value) =>
        value is not null
        && value.Length is >= VerifierMinimumLength and <= VerifierMaximumLength
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '~' or '-');
}
