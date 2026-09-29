using System.Collections.Concurrent;
using System.Data.Common;
using System.Diagnostics.Metrics;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Sms;
using SignaCore.Host.Services;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The commit-boundary contract of the <c>EV-36</c> SMS login transaction
/// (<see cref="OidcSmsLoginCompletionService"/>, #445) on both providers: the whole unit — the
/// continuation and OTP consumptions, <c>AutoProvision</c> provisioning, the <c>PS-04</c> recheck,
/// the <c>Sms</c> session, the code, the login info, and the masked audit — commits together or not
/// at all. A lost continuation is <c>EV-03</c>; a lost OTP consumption, a failed recheck, and a
/// second provisioning conflict are <c>EV-37</c>; a code-creation failure propagates; and
/// cancellation before the commit leaves nothing (<c>EV-18</c>). A unique-key conflict with a
/// concurrent provisioning of the same phone retries the unit once and reuses the winner's identity
/// (<c>SC-23</c>), and two consuming submissions of one continuation commit exactly once
/// (<c>SC-26</c>).
/// <para>
/// The SQLite form runs everywhere over a file database with a hand-installed retrying strategy
/// equivalent to the production PostgreSQL configuration. The PostgreSQL form runs the same cases
/// over the production <c>UseIdentityDatabase</c> configuration, plus the two true races, and is
/// gated on <c>RUN_SIGNACORE_DATABASE_CONTRACTS</c> like every <c>DatabaseContractTests</c> class.
/// </para>
/// </summary>
public sealed class OidcSmsLoginCompletionDatabaseContractTests
    : IClassFixture<OidcSmsLoginCompletionDatabaseContractTests.PostgreSqlDatabase>
{
    private const string RedirectUri = "https://bff.sms-completion.test/callback";
    private const string Scope = "openid profile";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string ClientIp = "203.0.113.45";
    private const string UserAgent = "sms-completion-agent";
    private const string CorrelationId = "sms-completion-correlation";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly PostgreSqlDatabase _postgres;

    public OidcSmsLoginCompletionDatabaseContractTests(PostgreSqlDatabase postgres)
    {
        _postgres = postgres;
    }

    public static TheoryData<string> Providers => new() { "SQLite", "PostgreSQL" };

    public enum RecheckBreak
    {
        AccountDisabled,
        AdmissionRevoked,
        NotAdminApprovedUnderManualApproval,
        ModeDisabled,
        NoIdentityUnderManualApproval
    }

    public static TheoryData<string, RecheckBreak> RecheckCases()
    {
        var data = new TheoryData<string, RecheckBreak>();
        foreach (var provider in new[] { "SQLite", "PostgreSQL" })
        foreach (var change in Enum.GetValues<RecheckBreak>())
        {
            data.Add(provider, change);
        }

        return data;
    }

    // ---- The committed unit ----

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task AnAdmittedPhone_CommitsTheWholeUnit(string provider)
    {
        await using var database = await OpenAsync(provider);
        var seed = await SeedAsync(database, SmsLoginMode.ManualApproval, Identity.AdminApproved);

        await using var unit = Build(database);
        var result = await unit.Service.CompleteAsync(Request(seed), Ct);

        var completed = Assert.IsType<OidcSmsLoginResult.Completed>(result);
        await using var db = database.Context();
        Assert.NotNull((await db.AuthorizationRequests.AsNoTracking().SingleAsync(row => row.Id == seed.ContinuationId, Ct)).ConsumedAt);
        Assert.Equal(OtpStatus.Consumed, (await OtpAsync(db, seed)).Status);
        var session = await db.IdentitySessions.AsNoTracking().SingleAsync(row => row.Id == completed.SessionId, Ct);
        Assert.Equal(IdentityConstants.AuthMethodSms, session.AuthMethod);
        Assert.Equal(seed.LoginId, session.SmsUserLoginId);
        Assert.Null(session.PasswordCredentialId);
        Assert.Equal(seed.AccountId, session.AccountId);
        var code = await db.AuthorizationCodes.AsNoTracking().SingleAsync(row => row.IdentitySessionId == session.Id, Ct);
        Assert.Equal(seed.ApplicationId, code.AppRegistrationId);
        Assert.Equal(RedirectUri, code.RedirectUri);
        Assert.Equal(Scope, code.Scope);
        var account = await db.Accounts.AsNoTracking().SingleAsync(row => row.Id == seed.AccountId, Ct);
        Assert.Equal(IdentityConstants.AuthMethodSms, account.LastLoginMethod);
        Assert.Equal(1, account.TotalLoginCount);
        var history = Assert.Single(await HistoriesAsync(db, seed));
        Assert.Equal(("login_success", "oidc_sms_login", (string?)null), (history.EventType, history.AuthMethod, history.FailureReason));
        Assert.Equal(seed.Phone[..3] + "****" + seed.Phone[^4..], history.Username);
        Assert.Equal(seed.AccountId, history.AccountId);
        Assert.Equal((seed.AppId, CorrelationId), (history.AppId, history.CorrelationId));
        Assert.Empty(await db.LoginAttempts.AsNoTracking().ToListAsync(Ct));
        Assert.Empty(unit.AccountCreations);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task AutoProvision_CreatesTheAccountIdentityAndAdmission_WithTheSessionAndCode(string provider)
    {
        await using var database = await OpenAsync(provider);
        var seed = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.None);

        await using var unit = Build(database);
        var completed = Assert.IsType<OidcSmsLoginResult.Completed>(await unit.Service.CompleteAsync(Request(seed), Ct));

        await using var db = database.Context();
        var login = await db.UserLogins.AsNoTracking().SingleAsync(row => row.ProviderUserId == seed.Phone, Ct);
        Assert.Equal(IdentityConstants.AuthMethodSms, login.ProviderName);
        var account = await db.Accounts.AsNoTracking().SingleAsync(row => row.Id == login.AccountId, Ct);
        Assert.True(account.IsActive);
        var access = await db.AppSmsAccesses.AsNoTracking().SingleAsync(row => row.UserLoginId == login.Id, Ct);
        Assert.Equal((seed.ApplicationId, SmsAccessApprovalSource.AutoProvision, true, (Guid?)null),
            (access.AppRegistrationId, access.ApprovalSource, access.IsActive, access.ApprovedBy));
        var session = await db.IdentitySessions.AsNoTracking().SingleAsync(row => row.Id == completed.SessionId, Ct);
        Assert.Equal((account.Id, (Guid?)login.Id), (session.AccountId, session.SmsUserLoginId));
        Assert.Equal(account.Id, Assert.Single(await HistoriesAsync(db, seed)).AccountId);
        Assert.Equal([OidcSmsLoginCompletionService.AccountCreationSource], unit.AccountCreations);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task AutoProvision_AddsOnlyTheMissingAdmission_ForAnIdentityOfAnotherApplication(string provider)
    {
        await using var database = await OpenAsync(provider);
        var seed = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.OtherApplicationOnly);

        await using var unit = Build(database);
        Assert.IsType<OidcSmsLoginResult.Completed>(await unit.Service.CompleteAsync(Request(seed), Ct));

        await using var db = database.Context();
        Assert.Equal(seed.LoginId, (await db.UserLogins.AsNoTracking().SingleAsync(row => row.ProviderUserId == seed.Phone, Ct)).Id);
        var accesses = await db.AppSmsAccesses.AsNoTracking().Where(row => row.UserLoginId == seed.LoginId).ToListAsync(Ct);
        Assert.Equal(2, accesses.Count);
        Assert.Equal(SmsAccessApprovalSource.AutoProvision, accesses.Single(row => row.AppRegistrationId == seed.ApplicationId).ApprovalSource);
        Assert.Empty(unit.AccountCreations);
    }

    // ---- The rolled-back races ----

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task AConsumedContinuation_IsUnavailable_AndNothingIsWritten(string provider)
    {
        await using var database = await OpenAsync(provider);
        var seed = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.None);
        await using (var db = database.Context())
        {
            Assert.True(await Continuations(db).TryConsumeAsync(seed.Handle, DateTimeOffset.UtcNow, Ct));
        }

        await using var unit = Build(database);
        Assert.IsType<OidcSmsLoginResult.ContinuationUnavailable>(await unit.Service.CompleteAsync(Request(seed), Ct));
        await AssertNothingCommittedAsync(database, seed, continuationConsumed: true);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task ALostOtpConsumption_IsAnSmsFailure_AndRollsTheContinuationBack(string provider)
    {
        await using var database = await OpenAsync(provider);
        var seed = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.None);

        // A send replaced the OTP after the read-only verification: the verified MAC is stale.
        await using (var db = database.Context())
        {
            await db.Otps.Where(row => row.Id == seed.OtpId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.CodeMac, new string('C', 64)), Ct);
        }

        await using var unit = Build(database);
        Assert.IsType<OidcSmsLoginResult.SmsFailure>(await unit.Service.CompleteAsync(Request(seed), Ct));
        await AssertNothingCommittedAsync(database, seed, otpStatus: OtpStatus.Sent);
    }

    [Theory]
    [MemberData(nameof(RecheckCases))]
    public async Task AFailedIdentityOrAdmissionRecheck_IsAnSmsFailure_AndRollsEverythingBack(string provider, RecheckBreak change)
    {
        await using var database = await OpenAsync(provider);
        var seed = await SeedAsync(
            database,
            SmsLoginMode.ManualApproval,
            change == RecheckBreak.NoIdentityUnderManualApproval ? Identity.None : Identity.AdminApproved);
        await using (var db = database.Context())
        {
            switch (change)
            {
                case RecheckBreak.AccountDisabled:
                    await db.Accounts.Where(row => row.Id == seed.AccountId)
                        .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false), Ct);
                    break;
                case RecheckBreak.AdmissionRevoked:
                    await db.AppSmsAccesses.Where(row => row.UserLoginId == seed.LoginId)
                        .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false), Ct);
                    break;
                case RecheckBreak.NotAdminApprovedUnderManualApproval:
                    await db.AppSmsAccesses.Where(row => row.UserLoginId == seed.LoginId)
                        .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.ApprovalSource, SmsAccessApprovalSource.AutoProvision), Ct);
                    break;
                case RecheckBreak.ModeDisabled:
                    await db.AppRegistrations.Where(row => row.Id == seed.ApplicationId)
                        .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SmsLoginMode, SmsLoginMode.Disabled), Ct);
                    break;
            }
        }

        var admissionsBefore = await AdmissionSnapshotAsync(database, seed);
        await using var unit = Build(database);
        Assert.IsType<OidcSmsLoginResult.SmsFailure>(await unit.Service.CompleteAsync(Request(seed), Ct));
        await AssertNothingCommittedAsync(database, seed, otpStatus: OtpStatus.Sent);
        Assert.Equal(admissionsBefore, await AdmissionSnapshotAsync(database, seed));
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task AnInactiveAdmission_IsNeverReactivated_UnderAutoProvision(string provider)
    {
        await using var database = await OpenAsync(provider);
        var seed = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.AdminApproved);
        await using (var db = database.Context())
        {
            await db.AppSmsAccesses.Where(row => row.UserLoginId == seed.LoginId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false), Ct);
        }

        await using var unit = Build(database);
        Assert.IsType<OidcSmsLoginResult.SmsFailure>(await unit.Service.CompleteAsync(Request(seed), Ct));
        await AssertNothingCommittedAsync(database, seed, otpStatus: OtpStatus.Sent);
        await using var check = database.Context();
        Assert.False((await check.AppSmsAccesses.AsNoTracking().SingleAsync(row => row.UserLoginId == seed.LoginId, Ct)).IsActive);
    }

    // ---- Failures and cancellation at the commit boundary ----

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task ACodeCreationFailure_Propagates_AndLeavesTheOtpUnconsumedAndNothingProvisioned(string provider)
    {
        await using var database = await OpenAsync(provider);
        var seed = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.None);

        await using var unit = Build(database, codes: _ => new ThrowingCodeStore());
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => unit.Service.CompleteAsync(Request(seed), Ct));
        Assert.DoesNotContain(seed.Phone, exception.Message, StringComparison.Ordinal);
        await AssertNothingCommittedAsync(database, seed, otpStatus: OtpStatus.Sent);
    }

    [Theory]
    [InlineData("SQLite", false)]
    [InlineData("SQLite", true)]
    [InlineData("PostgreSQL", false)]
    [InlineData("PostgreSQL", true)]
    public async Task CancellationAtTheCommitBoundary_EitherLeavesNothingOrStands(string provider, bool afterCommit)
    {
        using var cancellation = new CancellationTokenSource();
        var interceptor = new CommitCancellationInterceptor(cancellation, afterCommit);
        await using var database = await OpenAsync(provider, interceptor);
        var seed = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.None);

        await using var unit = Build(database);
        interceptor.Armed = true;
        if (afterCommit)
        {
            Assert.IsType<OidcSmsLoginResult.Completed>(await unit.Service.CompleteAsync(Request(seed), cancellation.Token));
            interceptor.Armed = false;

            // The committed result stands; a resubmission of the same form is EV-03.
            await using var retry = Build(database);
            Assert.IsType<OidcSmsLoginResult.ContinuationUnavailable>(await retry.Service.CompleteAsync(Request(seed), Ct));
            await using var db = database.Context();
            Assert.Single(await db.IdentitySessions.AsNoTracking().Where(row => row.SmsUserLoginId != null
                && db.UserLogins.Any(login => login.Id == row.SmsUserLoginId && login.ProviderUserId == seed.Phone)).ToListAsync(Ct));
            Assert.Equal(OtpStatus.Consumed, (await OtpAsync(db, seed)).Status);
        }
        else
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => unit.Service.CompleteAsync(Request(seed), cancellation.Token));
            await AssertNothingCommittedAsync(database, seed, otpStatus: OtpStatus.Sent);
        }

        Assert.Equal(1, interceptor.CommitAttempts);
        if (!afterCommit)
        {
            Assert.Empty(unit.AccountCreations);
        }
    }

    [Fact]
    public async Task ATransientFailure_ReplaysTheWholeUnitOnce()
    {
        var interceptor = new TransientFailureInterceptor("INSERT INTO \"login_histories\"", failuresToInject: 1);
        await using var database = await OpenAsync("SQLite", interceptor);
        var seed = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.None);

        await using var unit = Build(database);
        Assert.IsType<OidcSmsLoginResult.Completed>(await unit.Service.CompleteAsync(Request(seed), Ct));

        Assert.Equal(1, interceptor.InjectedFailures);
        await using var db = database.Context();
        Assert.Equal(1, await db.UserLogins.CountAsync(row => row.ProviderUserId == seed.Phone, Ct));
        Assert.Single(await HistoriesAsync(db, seed));
        Assert.Equal(OtpStatus.Consumed, (await OtpAsync(db, seed)).Status);
        Assert.Equal([OidcSmsLoginCompletionService.AccountCreationSource], unit.AccountCreations);
    }

    // ---- SC-23: provisioning conflicts ----

    /// <summary>
    /// The first lookup runs "before" a concurrent writer committed the phone's identity: it stages
    /// a second identity for the same phone, the flush hits the unique index, and the one retry
    /// finds and reuses the winner's identity, adding only this application's admission.
    /// </summary>
    [Theory]
    [MemberData(nameof(Providers))]
    public async Task AProvisioningConflict_RetriesOnce_AndReusesTheWinnersIdentity(string provider)
    {
        await using var database = await OpenAsync(provider);
        var seed = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.OtherApplicationOnly);

        await using var unit = Build(database, admissions: (inner, context) => new BlindLookup(inner, context, blindCalls: 1));
        var completed = Assert.IsType<OidcSmsLoginResult.Completed>(await unit.Service.CompleteAsync(Request(seed), Ct));

        await using var db = database.Context();
        Assert.Equal(seed.LoginId, (await db.UserLogins.AsNoTracking().SingleAsync(row => row.ProviderUserId == seed.Phone, Ct)).Id);
        Assert.Equal(1, await db.Accounts.CountAsync(row => row.Id == seed.AccountId, Ct));
        Assert.Equal(seed.LoginId, (await db.IdentitySessions.AsNoTracking().SingleAsync(row => row.Id == completed.SessionId, Ct)).SmsUserLoginId);
        Assert.Single(await db.AppSmsAccesses.AsNoTracking()
            .Where(row => row.AppRegistrationId == seed.ApplicationId && row.UserLoginId == seed.LoginId).ToListAsync(Ct));
        Assert.Empty(unit.AccountCreations);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task ASecondProvisioningConflict_IsAnSmsFailure_WithNothingCommitted(string provider)
    {
        await using var database = await OpenAsync(provider);
        var seed = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.OtherApplicationOnly);
        var before = await AdmissionSnapshotAsync(database, seed);

        await using var unit = Build(database, admissions: (inner, context) => new BlindLookup(inner, context, blindCalls: 2));
        Assert.IsType<OidcSmsLoginResult.SmsFailure>(await unit.Service.CompleteAsync(Request(seed), Ct));

        await AssertNothingCommittedAsync(database, seed, otpStatus: OtpStatus.Sent);
        Assert.Equal(before, await AdmissionSnapshotAsync(database, seed));
        await using var db = database.Context();
        Assert.Equal(1, await db.UserLogins.CountAsync(row => row.ProviderUserId == seed.Phone, Ct));
    }

    /// <summary>
    /// A true race on PostgreSQL: two applications log the same new phone in at once. Both units
    /// look the phone up and stage an identity before either flushes; the loser's flush waits on
    /// the unique index, fails with 23505 when the winner commits, and its retry reuses the
    /// winner's identity. Exactly one account and one identity result, with one admission each.
    /// </summary>
    [Fact]
    public async Task TwoApplicationsProvisioningOnePhone_OnPostgreSql_ProduceOneAccountAndIdentity()
    {
        await using var database = await OpenAsync("PostgreSQL");
        var first = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.None);
        var second = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.None, phone: first.Phone);
        var rendezvous = new Rendezvous(2);

        await using var a = Build(database, admissions: (inner, _) => new RendezvousAfterStaging(inner, rendezvous));
        await using var b = Build(database, admissions: (inner, _) => new RendezvousAfterStaging(inner, rendezvous));
        var results = await Task.WhenAll(
            Task.Run(() => a.Service.CompleteAsync(Request(first), Ct), Ct),
            Task.Run(() => b.Service.CompleteAsync(Request(second), Ct), Ct));

        Assert.All(results, result => Assert.IsType<OidcSmsLoginResult.Completed>(result));
        await using var db = database.Context();
        var login = await db.UserLogins.AsNoTracking().SingleAsync(row => row.ProviderUserId == first.Phone, Ct);
        Assert.Equal(1, await db.Accounts.CountAsync(row => row.Id == login.AccountId, Ct));
        Assert.Equal(
            new[] { first.ApplicationId, second.ApplicationId }.Order(),
            (await db.AppSmsAccesses.AsNoTracking().Where(row => row.UserLoginId == login.Id)
                .Select(row => row.AppRegistrationId).ToListAsync(Ct)).Order());
        Assert.Equal(2, await db.IdentitySessions.CountAsync(row => row.SmsUserLoginId == login.Id, Ct));
        Assert.Equal([OidcSmsLoginCompletionService.AccountCreationSource], a.AccountCreations.Concat(b.AccountCreations));
    }

    // ---- SC-26: two consuming submissions of one continuation ----

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task TwoSubmissionsOfOneContinuation_CommitExactlyOnce(string provider)
    {
        await using var database = await OpenAsync(provider);
        var seed = await SeedAsync(database, SmsLoginMode.AutoProvision, Identity.None);

        await using var a = Build(database);
        await using var b = Build(database);
        var results = await Task.WhenAll(
            Task.Run(() => CompleteOrUnavailableAsync(a, seed), Ct),
            Task.Run(() => CompleteOrUnavailableAsync(b, seed), Ct));

        Assert.Single(results, result => result is OidcSmsLoginResult.Completed);
        Assert.Single(results, result => result is not OidcSmsLoginResult.Completed);
        await using var db = database.Context();
        Assert.Equal(1, await db.UserLogins.CountAsync(row => row.ProviderUserId == seed.Phone, Ct));
        var loginId = await db.UserLogins.Where(row => row.ProviderUserId == seed.Phone).Select(row => row.Id).SingleAsync(Ct);
        Assert.Equal(1, await db.IdentitySessions.CountAsync(row => row.SmsUserLoginId == loginId, Ct));
        Assert.Single(await HistoriesAsync(db, seed));
    }

    /// <summary>
    /// SQLite serializes writers: a racer that cannot take the write lock within the busy timeout
    /// surfaces a busy error, which is still a loss that committed nothing. The race asserts the
    /// canonical invariant — one winner and no second session — for either loss shape.
    /// </summary>
    private static async Task<OidcSmsLoginResult?> CompleteOrUnavailableAsync(Unit unit, Seed seed)
    {
        try
        {
            return await unit.Service.CompleteAsync(Request(seed), Ct);
        }
        catch (Exception exception) when (exception is DbUpdateException or Microsoft.Data.Sqlite.SqliteException
            || exception.InnerException is Microsoft.Data.Sqlite.SqliteException)
        {
            return null;
        }
    }

    // ---- Assertions ----

    private static async Task AssertNothingCommittedAsync(
        Database database,
        Seed seed,
        bool continuationConsumed = false,
        OtpStatus otpStatus = OtpStatus.Sent)
    {
        await using var db = database.Context();
        Assert.Equal(continuationConsumed,
            (await db.AuthorizationRequests.AsNoTracking().SingleAsync(row => row.Id == seed.ContinuationId, Ct)).ConsumedAt is not null);
        Assert.Equal(otpStatus, (await OtpAsync(db, seed)).Status);
        var loginIds = await db.UserLogins.Where(row => row.ProviderUserId == seed.Phone).Select(row => row.Id).ToListAsync(Ct);
        Assert.Equal(seed.LoginId is null ? 0 : 1, loginIds.Count);
        Assert.Empty(await db.IdentitySessions.AsNoTracking()
            .Where(row => row.SmsUserLoginId != null && loginIds.Contains(row.SmsUserLoginId.Value)).ToListAsync(Ct));
        Assert.Empty(await db.AuthorizationCodes.AsNoTracking().Where(row => row.AppRegistrationId == seed.ApplicationId).ToListAsync(Ct));
        Assert.Empty(await HistoriesAsync(db, seed));
        if (seed.AccountId is { } accountId)
        {
            var account = await db.Accounts.AsNoTracking().SingleAsync(row => row.Id == accountId, Ct);
            Assert.Equal(0, account.TotalLoginCount);
        }
    }

    private static Task<List<LoginHistoryEntity>> HistoriesAsync(IdentityDbContext db, Seed seed) =>
        db.LoginHistories.AsNoTracking().Where(row => row.AppId == seed.AppId).ToListAsync(Ct);

    private static Task<OtpEntity> OtpAsync(IdentityDbContext db, Seed seed) =>
        db.Otps.AsNoTracking().SingleAsync(row => row.Id == seed.OtpId, Ct);

    private static async Task<string> AdmissionSnapshotAsync(Database database, Seed seed)
    {
        await using var db = database.Context();
        var rows = await db.AppSmsAccesses.AsNoTracking()
            .Where(row => db.UserLogins.Any(login => login.Id == row.UserLoginId && login.ProviderUserId == seed.Phone))
            .Select(row => row.Id + ":" + row.AppRegistrationId + ":" + row.IsActive + ":" + row.ApprovalSource)
            .ToListAsync(Ct);
        return string.Join('|', rows.Order(StringComparer.Ordinal));
    }

    // ---- Seeding ----

    public enum Identity
    {
        None,
        AdminApproved,
        OtherApplicationOnly
    }

    private sealed record Seed(
        Guid ApplicationId,
        string AppId,
        Guid ContinuationId,
        string Handle,
        string Phone,
        Guid OtpId,
        string CodeMac,
        Guid? AccountId,
        Guid? LoginId,
        OidcAuthorizationValidationResult.Accepted Accepted);

    private static async Task<Seed> SeedAsync(Database database, SmsLoginMode mode, Identity identity, string? phone = null)
    {
        await using var db = database.Context();
        var now = DateTimeOffset.UtcNow;
        phone ??= "+86139" + Random.Shared.NextInt64(0, 100_000_000).ToString("D8", System.Globalization.CultureInfo.InvariantCulture);
        var application = NewApplication(mode);
        db.AppRegistrations.Add(application);
        Guid? accountId = null;
        Guid? loginId = null;
        if (identity != Identity.None)
        {
            accountId = Guid.NewGuid();
            loginId = Guid.NewGuid();
            db.Accounts.Add(new AccountEntity { Id = accountId.Value, IsActive = true, CreatedAt = now });
            db.UserLogins.Add(new UserLoginEntity
            {
                Id = loginId.Value,
                AccountId = accountId.Value,
                ProviderName = IdentityConstants.AuthMethodSms,
                ProviderUserId = phone
            });
            var admittedApplication = application.Id;
            if (identity == Identity.OtherApplicationOnly)
            {
                var other = NewApplication(SmsLoginMode.AutoProvision);
                db.AppRegistrations.Add(other);
                admittedApplication = other.Id;
            }

            db.AppSmsAccesses.Add(new AppSmsAccessEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = admittedApplication,
                UserLoginId = loginId.Value,
                ApprovalSource = SmsAccessApprovalSource.Admin,
                IsActive = true,
                CreatedAt = now
            });
        }

        var codeMac = Convert.ToHexString(Guid.NewGuid().ToByteArray()) + Convert.ToHexString(Guid.NewGuid().ToByteArray());
        var otp = new OtpEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = application.Id,
            Phone = phone,
            CodeMac = codeMac,
            Status = OtpStatus.Sent,
            ExpiresAt = now.AddMinutes(5),
            LockoutUntil = DateTimeOffset.UnixEpoch,
            CreatedAt = now.AddMinutes(-1),
            HourWindowStartedAt = now.AddMinutes(-1),
            HourSendCount = 1,
            DayWindowStartedAt = now.AddMinutes(-1),
            DaySendCount = 1,
            Provider = "IntegrationFake",
            ProfileKey = "sms-completion-profile",
            Version = 1
        };
        db.Otps.Add(otp);
        await db.SaveChangesAsync(Ct);

        var accepted = new OidcAuthorizationValidationResult.Accepted(
            application.AppId, application.Id, RedirectUri, Scope,
            "state-" + Guid.NewGuid().ToString("N"), "nonce-" + Guid.NewGuid().ToString("N"), Challenge);
        var creation = await Continuations(db).CreateAsync(accepted, now.AddSeconds(-5), Ct);
        return new Seed(application.Id, application.AppId, creation.Id, creation.LoginHandle, phone, otp.Id, codeMac,
            accountId, loginId, accepted);
    }

    private static AppRegistrationEntity NewApplication(SmsLoginMode mode)
    {
        var id = Guid.NewGuid();
        return new AppRegistrationEntity
        {
            Id = id,
            AppId = "sms-completion-" + id.ToString("N")[..16],
            AppSecretHash = "unused-sms-completion-hash",
            AppName = "SMS Completion App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = Scope,
            AllowRefreshToken = false,
            SmsLoginMode = mode,
            SmsProfileKey = "sms-completion-profile",
            RedirectUris =
            [
                new AppRedirectUriEntity
                {
                    Id = Guid.NewGuid(),
                    AppRegistrationId = id,
                    Kind = RedirectUriKind.Redirect,
                    CanonicalUri = RedirectUri
                }
            ]
        };
    }

    private static OidcSmsLoginRequest Request(Seed seed) => new(
        seed.Handle,
        seed.Accepted,
        seed.AppId,
        seed.Phone,
        new OtpVerificationChange(
            OtpVerificationChangeKind.Consume,
            seed.ApplicationId,
            seed.Phone,
            seed.CodeMac,
            DateTimeOffset.UtcNow,
            5,
            DateTimeOffset.UtcNow.AddMinutes(15)),
        ClientIp,
        UserAgent,
        CorrelationId,
        DateTimeOffset.UtcNow);

    private static AuthorizationRequestStore Continuations(IdentityDbContext db) =>
        new(new AuthorizationRequestRepository(db), new EfCoreUnitOfWork(db));

    // ---- Unit under test ----

    private sealed class Unit(IdentityDbContext context, OidcSmsLoginCompletionService service, MeterListener listener,
        ConcurrentQueue<string> creations, ServiceProvider meters) : IAsyncDisposable
    {
        public OidcSmsLoginCompletionService Service => service;

        public IReadOnlyCollection<string> AccountCreations => creations;

        public async ValueTask DisposeAsync()
        {
            listener.Dispose();
            await meters.DisposeAsync();
            await context.DisposeAsync();
        }
    }

    private static Unit Build(
        Database database,
        Func<IAuthorizationCodeStore, IAuthorizationCodeStore>? codes = null,
        Func<ISmsAdmissionService, IdentityDbContext, ISmsAdmissionService>? admissions = null)
    {
        var context = database.Context();
        var unitOfWork = new EfCoreUnitOfWork(context);
        var accountRepository = new AccountRepository(context);
        var codeStore = new AuthorizationCodeStore(new AuthorizationCodeRepository(context), unitOfWork);
        var admissionService = new SmsAdmissionService(context);
        var meters = new ServiceCollection().AddMetrics().BuildServiceProvider();
        var meterFactory = meters.GetRequiredService<IMeterFactory>();
        var creations = new ConcurrentQueue<string>();
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Name == "auth.account.creation" && ReferenceEquals(instrument.Meter.Scope, meterFactory))
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<int>((_, _, tags, _) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Key == "source") creations.Enqueue(tag.Value?.ToString() ?? string.Empty);
            }
        });
        listener.Start();
        var service = new OidcSmsLoginCompletionService(
            Continuations(context),
            new OtpRepository(context),
            admissions?.Invoke(admissionService, context) ?? admissionService,
            accountRepository,
            new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork),
            codes?.Invoke(codeStore) ?? codeStore,
            new AccountLoginInfoService(accountRepository),
            new AuditService(new LoginHistoryRepository(context)),
            unitOfWork,
            context,
            new AuthMetrics(meterFactory),
            NullLogger<OidcSmsLoginCompletionService>.Instance);
        return new Unit(context, service, listener, creations, meters);
    }

    // ---- Databases ----

    private async Task<Database> OpenAsync(string provider, IInterceptor? interceptor = null)
    {
        if (provider == "PostgreSQL")
        {
            Assert.SkipUnless(_postgres.Enabled, "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL SMS login unit.");
            return new Database(_postgres.Options(interceptor), null);
        }

        var path = Path.Combine(Path.GetTempPath(), $"signacore-sms-completion-{Guid.NewGuid():N}.db");
        DbContextOptions<IdentityDbContext> Build(IInterceptor? withInterceptor)
        {
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseSqlite(
                $"Data Source={path};Default Timeout=30;Pooling=False",
                sqlite =>
                {
                    sqlite.MigrationsAssembly("SignaCore.Database.Migrations.Sqlite");
                    sqlite.ExecutionStrategy(dependencies => new TestRetryingExecutionStrategy(dependencies));
                });
            if (withInterceptor is not null)
            {
                builder.AddInterceptors(withInterceptor);
            }

            return builder.Options;
        }

        await using (var migration = new IdentityDbContext(Build(null)))
        {
            await migration.Database.MigrateAsync(Ct);
        }

        return new Database(Build(interceptor), path);
    }

    private sealed class Database(DbContextOptions<IdentityDbContext> options, string? sqlitePath) : IAsyncDisposable
    {
        public IdentityDbContext Context() => new(options);

        public ValueTask DisposeAsync()
        {
            if (sqlitePath is not null)
            {
                foreach (var file in new[] { sqlitePath, sqlitePath + "-wal", sqlitePath + "-shm" })
                {
                    if (File.Exists(file)) File.Delete(file);
                }
            }

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>One migrated PostgreSQL container for the class, started only when the matrix runs.</summary>
    public sealed class PostgreSqlDatabase : IAsyncLifetime
    {
        private PostgreSqlContainer? _container;
        private DatabaseOptions? _database;

        public bool Enabled => _database is not null;

        public DbContextOptions<IdentityDbContext> Options(IInterceptor? interceptor = null)
        {
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseIdentityDatabase(_database!);
            if (interceptor is not null)
            {
                builder.AddInterceptors(interceptor);
            }

            return builder.Options;
        }

        public async ValueTask InitializeAsync()
        {
            if (!bool.TryParse(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS"), out var run) || !run)
            {
                return;
            }

            _container = new PostgreSqlBuilder(
                    Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } image ? image : "postgres:15-alpine")
                .WithDatabase("identity")
                .WithUsername("postgres")
                .WithPassword("postgres")
                .Build();
            await _container.StartAsync();
            var database = new DatabaseOptions
            {
                Provider = "PostgreSQL",
                ServerVersion = "15",
                ConnectionString = _container.GetConnectionString()
            };
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseIdentityDatabase(database);
            await using var context = new IdentityDbContext(builder.Options);
            var deadline = DateTimeOffset.UtcNow.AddSeconds(120);
            while (!await context.Database.CanConnectAsync())
            {
                if (DateTimeOffset.UtcNow > deadline) throw new InvalidOperationException("The container database never became connectable.");
                await Task.Delay(250);
            }

            await context.Database.MigrateAsync();
            _database = database;
        }

        public async ValueTask DisposeAsync()
        {
            if (_container is not null)
            {
                await _container.DisposeAsync();
            }
        }
    }

    // ---- Seams ----

    private sealed class ThrowingCodeStore : IAuthorizationCodeStore
    {
        public Task<AuthorizationCodeCreation> CreateAsync(
            IdentitySessionEntity session, AuthorizationCodeBinding binding, DateTimeOffset now,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Simulated authorization code persistence failure.");

        public Task<AuthorizationCodeLookup> FindAsync(string code, DateTimeOffset now, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public bool VerifyBinding(AuthorizationCodeEntity code, Guid applicationId, string redirectUri, string codeVerifier) =>
            throw new NotSupportedException();

        public Task<AuthorizationCodeEntity?> LockAsync(Guid codeId, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<bool> TryConsumeAsync(Guid codeId, DateTimeOffset now, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<bool> LinkRefreshFamilyAsync(Guid codeId, Guid rootId, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<int> CleanupExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    /// <summary>
    /// Delegates every member; the first <c>blindCalls</c> identity lookups behave as if they ran
    /// before a concurrent writer committed the phone's identity and stage a second identity.
    /// </summary>
    private sealed class BlindLookup(ISmsAdmissionService inner, IdentityDbContext context, int blindCalls)
        : DelegatingAdmissions(inner)
    {
        private int _calls;

        public override async Task<SmsLoginIdentity?> FindOrStageLoginIdentityAsync(
            Guid appRegistrationId, SmsLoginMode mode, string phoneE164, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            if (_calls++ >= blindCalls)
            {
                return await base.FindOrStageLoginIdentityAsync(appRegistrationId, mode, phoneE164, now, cancellationToken);
            }

            var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = now };
            var login = new UserLoginEntity
            {
                Id = Guid.NewGuid(),
                AccountId = account.Id,
                ProviderName = IdentityConstants.AuthMethodSms,
                ProviderUserId = phoneE164
            };
            context.Accounts.Add(account);
            context.UserLogins.Add(login);
            return new SmsLoginIdentity(account.Id, login.Id, AccountCreated: true);
        }
    }

    private sealed class RendezvousAfterStaging(ISmsAdmissionService inner, Rendezvous rendezvous) : DelegatingAdmissions(inner)
    {
        private int _calls;

        public override async Task<SmsLoginIdentity?> FindOrStageLoginIdentityAsync(
            Guid appRegistrationId, SmsLoginMode mode, string phoneE164, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            var identity = await base.FindOrStageLoginIdentityAsync(appRegistrationId, mode, phoneE164, now, cancellationToken);
            if (_calls++ == 0)
            {
                await rendezvous.ArriveAsync();
            }

            return identity;
        }
    }

    private sealed class Rendezvous(int parties)
    {
        private readonly TaskCompletionSource _all = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _arrived;

        public async Task ArriveAsync()
        {
            if (Interlocked.Increment(ref _arrived) == parties)
            {
                _all.TrySetResult();
            }

            await _all.Task.WaitAsync(TimeSpan.FromSeconds(30), Ct);
        }
    }

    private abstract class DelegatingAdmissions(ISmsAdmissionService inner) : ISmsAdmissionService
    {
        protected ISmsAdmissionService Inner => inner;

        public Task<SmsAdmission?> FindAsync(Guid appRegistrationId, string phoneE164, CancellationToken cancellationToken = default) =>
            inner.FindAsync(appRegistrationId, phoneE164, cancellationToken);

        public Task<SmsAdmission?> FindByLoginIdAsync(Guid appRegistrationId, Guid userLoginId, CancellationToken cancellationToken = default) =>
            inner.FindByLoginIdAsync(appRegistrationId, userLoginId, cancellationToken);

        public Task<SmsSendEligibilityResult> EvaluateSendEligibilityAsync(
            Guid appRegistrationId, SmsLoginMode mode, string phoneE164, CancellationToken cancellationToken = default) =>
            inner.EvaluateSendEligibilityAsync(appRegistrationId, mode, phoneE164, cancellationToken);

        public Task<bool> IsSessionAdmittedAsync(
            Guid appRegistrationId, SmsLoginMode mode, Guid smsUserLoginId, CancellationToken cancellationToken = default) =>
            inner.IsSessionAdmittedAsync(appRegistrationId, mode, smsUserLoginId, cancellationToken);

        public virtual Task<SmsLoginIdentity?> FindOrStageLoginIdentityAsync(
            Guid appRegistrationId, SmsLoginMode mode, string phoneE164, DateTimeOffset now, CancellationToken cancellationToken = default) =>
            inner.FindOrStageLoginIdentityAsync(appRegistrationId, mode, phoneE164, now, cancellationToken);

        public Task<SmsAdmission> ProvisionAsync(
            AppRegistrationEntity app, string phoneE164, SmsAccessApprovalSource source, Guid? approvedBy,
            CancellationToken cancellationToken = default, Func<SmsAdmission, Task>? beforeCommit = null) =>
            inner.ProvisionAsync(app, phoneE164, source, approvedBy, cancellationToken, beforeCommit);

        public Task<SmsAdmission?> GrantByLoginIdAsync(
            AppRegistrationEntity app, Guid userLoginId, SmsAccessApprovalSource source, CancellationToken cancellationToken = default) =>
            inner.GrantByLoginIdAsync(app, userLoginId, source, cancellationToken);
    }

    private sealed class TestRetryingExecutionStrategy(ExecutionStrategyDependencies dependencies)
        : ExecutionStrategy(dependencies, maxRetryCount: 3, maxRetryDelay: TimeSpan.FromMilliseconds(1))
    {
        protected override bool ShouldRetryOn(Exception exception) =>
            exception is InjectedTransientException || exception.InnerException is InjectedTransientException;
    }

    private sealed class InjectedTransientException() : Exception("Injected transient database failure.");

    private sealed class CommitCancellationInterceptor(CancellationTokenSource cancellation, bool afterCommit)
        : DbTransactionInterceptor
    {
        public bool Armed { get; set; }

        public int CommitAttempts { get; private set; }

        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction, TransactionEventData eventData, InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            if (Armed)
            {
                CommitAttempts++;
                if (!afterCommit)
                {
                    cancellation.Cancel();
                    cancellationToken.ThrowIfCancellationRequested();
                }
            }

            return ValueTask.FromResult(result);
        }

        public override Task TransactionCommittedAsync(
            DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            if (Armed && afterCommit)
            {
                cancellation.Cancel();
            }

            return Task.CompletedTask;
        }
    }

    private sealed class TransientFailureInterceptor(string commandFragment, int failuresToInject) : DbCommandInterceptor
    {
        public int InjectedFailures { get; private set; }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfShouldFail(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfShouldFail(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void ThrowIfShouldFail(DbCommand command)
        {
            if (InjectedFailures >= failuresToInject
                || !command.CommandText.Contains(commandFragment, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            InjectedFailures++;
            throw new InjectedTransientException();
        }
    }
}
