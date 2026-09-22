using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using ServiceMantle.Audit;
using SignaCore.Database;
using SignaCore.Host.Audit;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Services;

/// <summary>
/// The routing result of <see cref="InteractiveRefreshRotationService.RotateAsync"/>: the
/// interactive branch either handled the request completely — an interactive rotation outcome or
/// a fail-closed corrupt/invalid answer — or reported <see cref="Handled"/>=false because the
/// presented credential is a legacy shape (or no digest row at all), leaving the legacy
/// <c>refresh_token</c> grant to answer with its unchanged wire behavior (<c>EV-33</c>).
/// </summary>
public sealed class InteractiveRefreshDispatch
{
    public bool Handled { get; private init; }

    public InteractiveRefreshRotationOutcome? Outcome { get; private init; }

    public static InteractiveRefreshDispatch NotInteractive { get; } = new() { Handled = false };

    public static InteractiveRefreshDispatch From(InteractiveRefreshRotationOutcome outcome) =>
        new() { Handled = true, Outcome = outcome };
}

/// <summary>
/// The one outcome shape of the interactive refresh branch: the HTTP status, the RFC 6749 error
/// code, the fixed English description, the closed-set metric reason, and — only on success —
/// the <c>PS-15</c> response members.
/// </summary>
public sealed class InteractiveRefreshRotationOutcome
{
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(AccessToken))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(IdToken))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(RefreshToken))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(Scope))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(false, nameof(ErrorCode))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(false, nameof(ErrorDescription))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(false, nameof(FailureReason))]
    public bool IsSuccess { get; private init; }

    /// <summary>The HTTP status the failure must be answered with; 0 on success.</summary>
    public int Status { get; private init; }

    public string? ErrorCode { get; private init; }

    public string? ErrorDescription { get; private init; }

    /// <summary>The closed metric reason: invalid_request, invalid_client, invalid_grant, replay, server_error.</summary>
    public string? FailureReason { get; private init; }

    public string? AccessToken { get; private init; }

    /// <summary>The nonce-free ID token (<c>PS-12</c>/<c>PS-15</c>) of the same committed rotation.</summary>
    public string? IdToken { get; private init; }

    /// <summary>
    /// The plaintext child refresh token of the committed rotation (<c>EV-29</c>/<c>PS-15</c>),
    /// returned exactly once and never persisted.
    /// </summary>
    public string? RefreshToken { get; private init; }

    public long ExpiresIn { get; private init; }

    /// <summary>The family's unchanged canonical scope snapshot, echoed byte for byte in the response.</summary>
    public string? Scope { get; private init; }

    public static InteractiveRefreshRotationOutcome Success(
        string accessToken,
        string idToken,
        string refreshToken,
        long expiresIn,
        string scope) => new()
    {
        IsSuccess = true,
        AccessToken = accessToken,
        IdToken = idToken,
        RefreshToken = refreshToken,
        ExpiresIn = expiresIn,
        Scope = scope
    };

    public static InteractiveRefreshRotationOutcome Failure(
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
/// The interactive <c>refresh_token</c> branch of <c>POST /oauth2/token</c> (<c>EV-29</c>–
/// <c>EV-32</c>): one atomic rotation of an interactive family member — consume the presented
/// token, insert exactly one child, and release the <c>PS-15</c> response only after the commit.
/// A correctly bound consumed member is reuse (<c>EV-31</c>): every live descendant of the
/// presented member is revoked, one id-only <c>oidc.refresh.replayed</c> audit is committed, the
/// identity session is <b>not</b> revoked, and the answer is the single generic
/// <c>invalid_grant</c>. Session expiry, a missing session row, application max-age, and scope
/// removal revoke the family atomically inside the rejecting transaction (<c>EV-32</c>); every
/// other rejection — wrong client, corrupt marker or binding, an explicitly revoked or expired
/// member, an inactive account or application — fails closed with the same generic
/// <c>invalid_grant</c> and zero writes (<c>SC-18</c>). Legacy rows never enter this service
/// (<c>EV-33</c>); the dispatch keeps their wire behavior byte for byte.
/// </summary>
/// <remarks>
/// Same transaction shape as <see cref="AuthorizationCodeRedemptionService"/>: the explicit
/// transaction runs as a whole inside <c>CreateExecutionStrategy()</c> (<c>PS-22</c>), the locks
/// follow the canonical session-root-member order (<c>Persistence.md</c>), and no external HTTP
/// runs under a held lock — the refresh path performs none at all. The child id, raw token, and
/// digest are generated once per HTTP attempt, outside the strategy lambda, so a replayed
/// attempt reuses the same bytes, never creates a second child, and recognizes its own committed
/// child instead of classifying itself as an attack.
/// </remarks>
public sealed class InteractiveRefreshRotationService(
    IRefreshTokenRepository refreshTokens,
    IRefreshTokenFamilyStore refreshFamilies,
    IIdentitySessionStore identitySessions,
    IAccountRepository accounts,
    IPasswordCredentialRepository passwordCredentials,
    IInteractiveAccessTokenFactory tokenFactory,
    IInteractiveIdTokenFactory idTokenFactory,
    IKeyManager keyManager,
    IManagementAuditWriter auditWriter,
    AuthMetrics authMetrics,
    IUnitOfWork unitOfWork,
    IdentityDbContext dbContext,
    ILogger<InteractiveRefreshRotationService> logger)
{
    public const string GrantType = IdentityConstants.GrantTypeRefreshToken;

    private const string ReplayedAuditAction = "oidc.refresh.replayed";
    private const string FamilyAuditTargetType = "RefreshTokenFamily";

    // Every rejection of a digest-matched interactive member shares one description; which
    // predicate failed is never disclosed.
    private const string InvalidRefreshGrantDescription = "The refresh token is invalid.";
    private const string MalformedRequestDescription = "A token request parameter is missing or malformed.";
    private const string ScopeNotAcceptedDescription =
        "The refresh token grant does not accept a scope parameter.";
    private const string MixedClientCredentialsDescription =
        "This client is not permitted to combine client authentication methods.";
    private const string ServerErrorDescription =
        "The authorization server could not complete the token request.";

    private const int RefreshTokenMinimumLength = 1;
    private const int RefreshTokenMaximumLength = 256;

    /// <summary>
    /// Runs the whole refresh decision under one caller-captured UTC instant (<c>PS-22</c>).
    /// The caller has already authenticated the client and computed
    /// <paramref name="clientCredentialMixPresent"/> by the client-authentication handler's own
    /// parse rules (<c>IN-20</c>).
    /// </summary>
    /// <exception cref="OperationCanceledException">
    /// The caller's token was cancelled; every write rolled back and no error body was produced
    /// (<c>EV-18</c>).
    /// </exception>
    public async Task<InteractiveRefreshDispatch> RotateAsync(
        AppRegistrationEntity app,
        IFormCollection form,
        bool clientCredentialMixPresent,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(form);

        var stopwatch = Stopwatch.StartNew();
        InteractiveRefreshDispatch dispatch;
        try
        {
            dispatch = await RotateCoreAsync(
                app, form, clientCredentialMixPresent, clientIp, correlationId, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // EV-26: signing, persistence, or commit failure — everything rolled back and no
            // token bytes released; the response is the single 500 server_error.
            logger.LogError(ex,
                "Interactive refresh rotation failed before commit: AppId={AppId}, CorrelationId={CorrelationId}",
                LogValueSanitizer.Sanitize(app.AppId),
                LogValueSanitizer.Sanitize(correlationId));
            dispatch = InteractiveRefreshDispatch.From(InteractiveRefreshRotationOutcome.Failure(
                StatusCodes.Status500InternalServerError,
                OAuthErrorCodes.ServerError,
                ServerErrorDescription,
                "server_error"));
        }

        stopwatch.Stop();
        if (dispatch.Handled && dispatch.Outcome is { } outcome)
        {
            if (outcome.IsSuccess)
            {
                authMetrics.RecordLoginSuccess(GrantType);
            }
            else
            {
                authMetrics.RecordLoginFailure(GrantType, outcome.FailureReason!);
            }

            authMetrics.RecordLoginDuration(stopwatch.Elapsed.TotalMilliseconds, GrantType);
        }

        return dispatch;
    }

    private async Task<InteractiveRefreshDispatch> RotateCoreAsync(
        AppRegistrationEntity app,
        IFormCollection form,
        bool clientCredentialMixPresent,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        // IN-26: exactly one refresh_token value of the bounded ASCII shape. The malformed-input
        // contract is branch-wide per the canonical model; every valid-shape legacy presentation
        // still falls through to the legacy grant unchanged.
        if (!TryReadSingleFormValue(form, "refresh_token", out var refreshToken)
            || !IsRefreshTokenShape(refreshToken))
        {
            return InteractiveRefreshDispatch.From(InteractiveRefreshRotationOutcome.Failure(
                StatusCodes.Status400BadRequest,
                OAuthErrorCodes.InvalidRequest,
                MalformedRequestDescription,
                "invalid_request"));
        }

        // One captured instant for every comparison and write of this rotation (PS-22).
        var now = DateTimeOffset.UtcNow;

        // The digest lookup identifies the member without granting authority; a missing row is
        // the legacy grant's business (SC-18: no invented state).
        var member = await refreshTokens.GetByTokenValueAsync(refreshToken, cancellationToken);
        if (member is null)
        {
            return InteractiveRefreshDispatch.NotInteractive;
        }

        var marker = RefreshTokenFamilyStore.ClassifyMarker(member);
        if (marker == RefreshMemberMarker.Legacy)
        {
            return InteractiveRefreshDispatch.NotInteractive;
        }

        if (marker == RefreshMemberMarker.Partial)
        {
            // Corrupt state no writer of either kind can produce: fail closed with the generic
            // answer and zero side effects, keeping the detail in a non-secret log line only.
            logger.LogWarning(
                "Refresh token rejected: a partially marked refresh_tokens row was presented, MemberId={MemberId}",
                member.Id);
            return InteractiveRefreshDispatch.From(InvalidGrant());
        }

        // IN-20: the interactive branch refuses the Basic-plus-form credential mix the handler
        // itself would have accepted.
        if (clientCredentialMixPresent)
        {
            return InteractiveRefreshDispatch.From(InteractiveRefreshRotationOutcome.Failure(
                StatusCodes.Status401Unauthorized,
                OAuthErrorCodes.InvalidClient,
                MixedClientCredentialsDescription,
                "invalid_client"));
        }

        // IN-27: the family snapshot is authoritative and can never be narrowed or replaced.
        if (form.ContainsKey("scope"))
        {
            return InteractiveRefreshDispatch.From(InteractiveRefreshRotationOutcome.Failure(
                StatusCodes.Status400BadRequest,
                OAuthErrorCodes.InvalidRequest,
                ScopeNotAcceptedDescription,
                "invalid_request"));
        }

        // The non-authoritative prechecks over stable, immutable facts keep doomed requests out
        // of the transaction; every authoritative decision is repeated under the locks below.
        // Wrong client is a static binding failure and never reaches any side effect.
        if (!string.Equals(member.AppId, app.AppId, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "Interactive refresh rejected: the presented member belongs to another client, MemberId={MemberId}",
                member.Id);
            return InteractiveRefreshDispatch.From(InvalidGrant());
        }

        // Committed consumption is immutable and outranks every other observation (EV-31); a
        // revoked or expired member never manufactures reuse or a write (EV-32).
        if (member.ConsumedAt is not null)
        {
            return InteractiveRefreshDispatch.From(await ExecuteRotationTransactionAsync(
                app, member, passwordUsername: null, displayName: null, signingKey: null,
                now, clientIp, correlationId, cancellationToken));
        }

        if (member.IsRevoked || now >= member.ExpiresAt)
        {
            return InteractiveRefreshDispatch.From(InvalidGrant());
        }

        // Profile sources for both constructors, resolved outside the transaction like the
        // redemption's — the locked rows re-supply the authoritative values below.
        var account = await accounts.GetByIdAsync(member.AccountId, cancellationToken);
        if (account is null || !account.IsActive)
        {
            return InteractiveRefreshDispatch.From(InvalidGrant());
        }

        var passwordUsername = await ResolvePasswordUsernameAsync(account, cancellationToken);
        var displayName = !string.IsNullOrWhiteSpace(account.Nickname)
            ? account.Nickname
            : passwordUsername;

        await keyManager.RefreshKeysAsync(cancellationToken);
        var signingKey = keyManager.GetCurrentKey();

        return InteractiveRefreshDispatch.From(await ExecuteRotationTransactionAsync(
            app,
            member,
            passwordUsername,
            displayName,
            signingKey,
            now,
            clientIp,
            correlationId,
            cancellationToken));
    }

    /// <summary>
    /// The <c>EV-29</c>–<c>EV-32</c> transaction: session lock first, then the family root, then
    /// the presented member; the authoritative binding, state, and live-predicate rechecks under
    /// the captured instant; both signatures; the conditional consumption; the unique child; and
    /// the commit — after which, and only after which, the token bytes leave this service.
    /// </summary>
    private async Task<InteractiveRefreshRotationOutcome> ExecuteRotationTransactionAsync(
        AppRegistrationEntity app,
        RefreshTokenEntity member,
        string? passwordUsername,
        string? displayName,
        RsaSecurityKey? signingKey,
        DateTimeOffset now,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        // Request-local stable child values: generated once per HTTP attempt, outside the
        // strategy lambda, so a replayed attempt reuses the same bytes and recognizes its own
        // committed child instead of minting a second one.
        var childId = Guid.NewGuid();
        var childToken = RefreshTokenFamilyStore.GenerateRefreshToken();
        var childDigest = RefreshTokenDigest.Compute(childToken);

        var strategy = dbContext.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async operationToken =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction = await dbContext.Database
                .BeginTransactionAsync(operationToken);

            // Persistence.md lock order: the loser of a concurrent rotation observes the
            // committed consumption under these locks and runs the reuse disposal instead.
            var lockedSession = await identitySessions.LockAsync(
                member.IdentitySessionId!.Value, operationToken);
            var lockedRoot = await refreshTokens.LockByIdAsync(member.FamilyId, operationToken);
            var lockedMember = member.Id == member.FamilyId
                ? lockedRoot
                : await refreshTokens.LockByIdAsync(member.Id, operationToken);

            // The authoritative static binding rechecks: exact client, complete markers, the
            // root shape, the member's place in the family, byte-for-byte member/root bindings,
            // and a consistent parent link. Any drift is corrupt state — the generic answer, no
            // reuse side effect (SC-18 discipline).
            if (lockedRoot is null
                || lockedMember is null
                || !string.Equals(lockedMember.AppId, app.AppId, StringComparison.Ordinal)
                || RefreshTokenFamilyStore.ClassifyMarker(lockedMember) != RefreshMemberMarker.Interactive
                || lockedRoot.Id != lockedRoot.FamilyId
                || RefreshTokenFamilyStore.ClassifyMarker(lockedRoot) != RefreshMemberMarker.Interactive
                || lockedMember.FamilyId != lockedRoot.Id
                || !HasConsistentFamilyBindings(lockedRoot, lockedMember)
                || (lockedMember.ParentId is Guid parentId
                    && !await HasConsistentParentAsync(parentId, lockedRoot, lockedMember, operationToken)))
            {
                await transaction.RollbackAsync(operationToken);
                logger.LogWarning(
                    "Interactive refresh rejected: inconsistent family binding, RootId={RootId}, MemberId={MemberId}",
                    member.FamilyId,
                    member.Id);
                return InvalidGrant();
            }

            // EV-31: committed consumption alone proves reuse — independent of session state,
            // expiry, or revocation — for a correctly bound member.
            if (lockedMember.ConsumedAt is not null)
            {
                return await CommitReuseDisposalAsync(
                    lockedMember, lockedRoot, app, transaction, now, clientIp, correlationId, operationToken);
            }

            if (lockedMember.IsRevoked || now >= lockedMember.ExpiresAt)
            {
                await transaction.RollbackAsync(operationToken);
                return InvalidGrant();
            }

            // The current application policy is re-read under the same captured instant; the
            // capability rejections leave the family to their own state transactions
            // (EV-09/EV-11) and only fail closed here.
            var currentApplication = await ReadApplicationAsync(app.Id, operationToken);
            if (currentApplication is null
                || !currentApplication.IsActive
                || !currentApplication.AllowRefreshToken)
            {
                await transaction.RollbackAsync(operationToken);
                return InvalidGrant();
            }

            // The EV-32 rejections that revoke the family atomically inside this rejecting
            // transaction, each with its closed cause.
            if (lockedSession is null)
            {
                return await CommitFamilyRevocationAsync(
                    lockedRoot.Id,
                    RefreshFamilyRevocationReason.SessionMissing,
                    transaction,
                    operationToken);
            }

            var sessionState = IdentitySessionStore.Classify(lockedSession, now);
            if (sessionState != IdentitySessionState.Active)
            {
                return await CommitFamilyRevocationAsync(
                    lockedRoot.Id,
                    RefreshFamilyRevocationReason.SessionExpired,
                    transaction,
                    operationToken);
            }

            if (FailsApplicationSessionPolicy(currentApplication, lockedSession, now))
            {
                return await CommitFamilyRevocationAsync(
                    lockedRoot.Id,
                    RefreshFamilyRevocationReason.ApplicationMaxAge,
                    transaction,
                    operationToken);
            }

            if (!IsScopeStillAllowed(lockedMember.Scope!, currentApplication.AllowedScopes))
            {
                return await CommitFamilyRevocationAsync(
                    lockedRoot.Id,
                    RefreshFamilyRevocationReason.ScopeRemoved,
                    transaction,
                    operationToken);
            }

            var lockedAccount = await accounts.GetByIdAsync(lockedMember.AccountId, operationToken);
            if (lockedAccount is null || !lockedAccount.IsActive)
            {
                await transaction.RollbackAsync(operationToken);
                return InvalidGrant();
            }

            // EV-26: a failing or oversized construction of either token rolls the consumption
            // back with everything else — the fallible steps precede the parent's consumption.
            if (signingKey is null
                || tokenFactory.Create(
                    new InteractiveAccessTokenDescriptor(
                        lockedAccount.Id,
                        app.AppId,
                        lockedSession.Id,
                        lockedSession.AuthMethod,
                        lockedMember.Scope!,
                        displayName,
                        lockedAccount.Nickname,
                        EnrichmentClaims: []),
                    signingKey,
                    now)
                is not InteractiveAccessTokenResult.Issued issued)
            {
                await transaction.RollbackAsync(operationToken);
                return ServerError();
            }

            // PS-15: the refreshed ID token omits the nonce and carries the original auth facts.
            if (idTokenFactory.Create(
                    new InteractiveIdTokenDescriptor(
                        lockedAccount.Id,
                        app.AppId,
                        lockedSession.Id,
                        lockedSession.AuthMethod,
                        lockedMember.Scope!,
                        Nonce: null,
                        lockedMember.AuthTime!.Value,
                        passwordUsername,
                        lockedAccount.Nickname),
                    signingKey,
                    now)
                is not InteractiveIdTokenResult.Issued issuedIdToken)
            {
                await transaction.RollbackAsync(operationToken);
                return ServerError();
            }

            if (!await refreshFamilies.TryConsumeAsync(lockedMember.Id, now, operationToken))
            {
                // Either an earlier attempt of this same request already committed, or another
                // caller's rotation won the race. The stable child id/digest tells them apart
                // (PS-22): resuming our own commit is idempotency, never an attack.
                var existingChild = await refreshTokens.GetByIdAsync(childId, operationToken);
                if (existingChild is not null
                    && string.Equals(existingChild.TokenValue, childDigest, StringComparison.Ordinal)
                    && existingChild.ParentId == lockedMember.Id
                    && existingChild.FamilyId == lockedRoot.Id)
                {
                    await transaction.CommitAsync(operationToken);
                    logger.LogInformation(
                        "Resumed an already committed interactive rotation: RootId={RootId}, ChildId={ChildId}",
                        lockedRoot.Id,
                        childId);
                    return InteractiveRefreshRotationOutcome.Success(
                        issued.AccessToken,
                        issuedIdToken.IdToken,
                        childToken,
                        IdentityConstants.InteractiveAccessTokenLifetimeSeconds,
                        lockedMember.Scope!);
                }

                return await CommitReuseDisposalAsync(
                    lockedMember, lockedRoot, app, transaction, now, clientIp, correlationId, operationToken);
            }

            // EV-29: the child copies the root's bindings and deadline byte for byte; the unique
            // parent index is the database backstop for the one-child invariant.
            await refreshFamilies.CreateChildAsync(
                new InteractiveRefreshChildDescriptor(
                    childId,
                    lockedMember.Id,
                    lockedRoot.Id,
                    lockedAccount.Id,
                    app.AppId,
                    lockedSession.Id,
                    lockedMember.Scope!,
                    lockedMember.AuthTime!.Value,
                    lockedMember.ExpiresAt,
                    childDigest),
                now,
                operationToken);
            await unitOfWork.SaveChangesAsync(operationToken);
            await transaction.CommitAsync(operationToken);

            logger.LogInformation(
                "Interactive refresh token rotated: AccountId={AccountId}, AppId={AppId}, RootId={RootId}, ChildId={ChildId}",
                lockedAccount.Id,
                LogValueSanitizer.Sanitize(app.AppId),
                lockedRoot.Id,
                childId);
            return InteractiveRefreshRotationOutcome.Success(
                issued.AccessToken,
                issuedIdToken.IdToken,
                childToken,
                IdentityConstants.InteractiveAccessTokenLifetimeSeconds,
                lockedMember.Scope!);
        }, cancellationToken);
    }

    /// <summary>
    /// The <c>EV-31</c> disposal for a correctly bound consumed member: revoke every live
    /// descendant in the family, stage exactly one id-only <c>oidc.refresh.replayed</c> audit —
    /// family id, member id, bounded revoked count, and application id, never a token or digest —
    /// and answer with the generic <c>invalid_grant</c> after the commit. The session is not
    /// revoked.
    /// </summary>
    private async Task<InteractiveRefreshRotationOutcome> CommitReuseDisposalAsync(
        RefreshTokenEntity lockedMember,
        RefreshTokenEntity lockedRoot,
        AppRegistrationEntity app,
        IDbContextTransaction transaction,
        DateTimeOffset now,
        string? clientIp,
        string? correlationId,
        CancellationToken operationToken)
    {
        var revoked = await refreshFamilies.RevokeLiveDescendantsAsync(
            lockedRoot.Id, lockedMember.Id, RefreshFamilyRevocationReason.RefreshReuse, operationToken);
        await ManagementActionAudit.RecordAsync(
            auditWriter,
            ManagementActionAudit.AccountSource,
            ReplayedAuditAction,
            FamilyAuditTargetType,
            lockedRoot.Id.ToString("D"),
            lockedMember.AccountId,
            null,
            $"family:{lockedRoot.Id:D};member:{lockedMember.Id:D};revoked:{revoked};app:{app.AppId}",
            clientIp,
            correlationId,
            cancellationToken: operationToken);
        await unitOfWork.SaveChangesAsync(operationToken);
        await transaction.CommitAsync(operationToken);

        logger.LogWarning(
            "Interactive refresh token reuse detected and live descendants revoked: RootId={RootId}, MemberId={MemberId}, Revoked={Revoked}",
            lockedRoot.Id,
            lockedMember.Id,
            revoked);
        return InteractiveRefreshRotationOutcome.Failure(
            StatusCodes.Status400BadRequest,
            OAuthErrorCodes.InvalidGrant,
            InvalidRefreshGrantDescription,
            "replay");
    }

    /// <summary>
    /// One <c>EV-32</c> rejection whose canonical ledger row revokes the family atomically
    /// inside this rejecting transaction, with the closed cause recorded in the family store's
    /// log; the answer after the commit is the same generic <c>invalid_grant</c> as every other
    /// rejection, and no reuse audit is emitted.
    /// </summary>
    private async Task<InteractiveRefreshRotationOutcome> CommitFamilyRevocationAsync(
        Guid rootId,
        RefreshFamilyRevocationReason reason,
        IDbContextTransaction transaction,
        CancellationToken operationToken)
    {
        await refreshFamilies.RevokeFamilyAsync(rootId, reason, operationToken);
        await unitOfWork.SaveChangesAsync(operationToken);
        await transaction.CommitAsync(operationToken);
        return InvalidGrant();
    }

    /// <summary>
    /// The root and member carry byte-for-byte identical family bindings and deadline
    /// (<c>PS-06</c>): account, client, session, canonical scope, auth time, and expiry.
    /// </summary>
    private static bool HasConsistentFamilyBindings(
        RefreshTokenEntity root,
        RefreshTokenEntity member) =>
        root.AccountId == member.AccountId
        && string.Equals(root.AppId, member.AppId, StringComparison.Ordinal)
        && root.IdentitySessionId == member.IdentitySessionId
        && string.Equals(root.Scope, member.Scope, StringComparison.Ordinal)
        && root.AuthTime == member.AuthTime
        && root.ExpiresAt == member.ExpiresAt;

    /// <summary>
    /// A child's parent must be a retained interactive member of the same family with the same
    /// byte-for-byte bindings. The read is unlocked: family rows are only written under the root
    /// lock this transaction already holds.
    /// </summary>
    private async Task<bool> HasConsistentParentAsync(
        Guid parentId,
        RefreshTokenEntity lockedRoot,
        RefreshTokenEntity lockedMember,
        CancellationToken operationToken)
    {
        var parent = await refreshTokens.GetByIdAsync(parentId, operationToken);
        return parent is not null
            && parent.FamilyId == lockedRoot.Id
            && parent.IdentitySessionId == lockedMember.IdentitySessionId
            && HasConsistentFamilyBindings(lockedRoot, parent);
    }

    private async Task<AppRegistrationEntity?> ReadApplicationAsync(
        Guid applicationRowId,
        CancellationToken cancellationToken) =>
        await dbContext.AppRegistrations
            .AsNoTracking()
            .SingleOrDefaultAsync(application => application.Id == applicationRowId, cancellationToken);

    /// <summary>
    /// <c>EV-05</c>: the per-application session max-age, evaluated against the re-read
    /// application inside the transaction — the same predicate as the code redemption's, kept as
    /// a semantic copy rather than a cross-layer reference.
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
        return scopeSnapshot.Split(' ', StringSplitOptions.RemoveEmptyEntries).All(allowed.Contains);
    }

    /// <summary>
    /// The bound Password username of the account, or null when the account has no password
    /// credential — the same source the redemption's ID-token <c>name</c> claim uses.
    /// </summary>
    private async Task<string?> ResolvePasswordUsernameAsync(
        AccountEntity account,
        CancellationToken cancellationToken)
    {
        var credential = await passwordCredentials.GetByAccountIdAsync(account.Id, cancellationToken);
        return credential?.Username;
    }

    private static InteractiveRefreshRotationOutcome InvalidGrant() =>
        InteractiveRefreshRotationOutcome.Failure(
            StatusCodes.Status400BadRequest,
            OAuthErrorCodes.InvalidGrant,
            InvalidRefreshGrantDescription,
            "invalid_grant");

    private static InteractiveRefreshRotationOutcome ServerError() =>
        InteractiveRefreshRotationOutcome.Failure(
            StatusCodes.Status500InternalServerError,
            OAuthErrorCodes.ServerError,
            ServerErrorDescription,
            "server_error");

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

    /// <summary>
    /// The <c>IN-26</c> shape: 1–256 printable ASCII characters, not whitespace-only — a value
    /// the digest function could never have been computed from is malformed input.
    /// </summary>
    private static bool IsRefreshTokenShape(string? value) =>
        value is not null
        && value.Length is >= RefreshTokenMinimumLength and <= RefreshTokenMaximumLength
        && !string.IsNullOrWhiteSpace(value)
        && value.All(character => character is >= ' ' and <= '~');
}
