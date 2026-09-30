using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using ServiceMantle.Persistence.Relational;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Database;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Services;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Services;

/// <summary>
/// The <c>EV-35</c> send unit as a unit (#444): the per-continuation slot is taken before any
/// phone-dependent read, every absorbed case commits one masked <c>sms_code_suppressed</c> row
/// with its closed reason, a delivered code commits one <c>sms_code_sent</c> row, a failure after
/// the count is <c>persistence_failed</c>, and cancellation before the count leaves nothing while
/// cancellation after it keeps the slot taken (<c>EV-18</c>).
/// </summary>
public sealed class OidcSmsCodeSendServiceTests : IAsyncLifetime
{
    private const string AppId = "sms-send-unit-app";
    private const string Phone = "+8613912345678";
    private const string MaskedPhone = "+86****5678";
    private const string CorrelationId = "sms-send-unit-correlation";

    private readonly Mock<ISmsAdmissionService> _admissions = new(MockBehavior.Strict);
    private readonly Mock<IOtpService> _otp = new(MockBehavior.Strict);
    private readonly List<string> _calls = [];
    private SqliteConnection _connection = null!;
    private IdentityDbContext _context = null!;
    private AuthorizationRequestStore _store = null!;
    private Guid _applicationId;
    private Guid _continuationId;
    private string _handle = null!;

    public async ValueTask InitializeAsync()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        await _connection.OpenAsync(TestContext.Current.CancellationToken);
        _context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(_connection).Options);
        await _context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        _applicationId = Guid.NewGuid();
        _context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = _applicationId,
            AppId = AppId,
            AppName = AppId,
            AppSecretHash = "unused-test-hash",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            SmsLoginMode = SmsLoginMode.ManualApproval,
            SmsProfileKey = "test"
        });
        await _context.SaveChangesAsync(TestContext.Current.CancellationToken);
        _store = new AuthorizationRequestStore(new AuthorizationRequestRepository(_context), new EfCoreUnitOfWork(_context));
        var creation = await _store.CreateAsync(
            new OidcAuthorizationValidationResult.Accepted(
                AppId, _applicationId, "https://bff.sms-unit.test/callback", "openid",
                "sms-unit-state-0123456789ab", "sms-unit-nonce-0123456789ab",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            DateTimeOffset.UtcNow.AddMinutes(-1),
            TestContext.Current.CancellationToken);
        _handle = creation.LoginHandle;
        _continuationId = creation.Id;
        _context.ChangeTracker.Clear();
    }

    public async ValueTask DisposeAsync()
    {
        await _context.DisposeAsync();
        await _connection.DisposeAsync();
    }

    [Fact]
    public async Task AnExhaustedContinuationBudget_ReadsNothingAboutThePhone()
    {
        await SetCountAsync(IdentityConstants.MaxSmsCodeSendsPerContinuation);

        var outcome = await CreateService().SendAsync(Request(), TestContext.Current.CancellationToken);

        Assert.Equal(OidcSmsCodeSendOutcomes.ContinuationBudget, outcome);
        _admissions.VerifyNoOtherCalls();
        _otp.VerifyNoOtherCalls();
        var row = Assert.Single(await HistoriesAsync());
        AssertAudit(row, OidcSmsCodeSendService.SuppressedEventType, "continuation_budget", accountId: null);
        Assert.Equal(IdentityConstants.MaxSmsCodeSendsPerContinuation, await CountAsync());
    }

    [Theory]
    [InlineData(SmsSendEligibility.NotRegistered, "not_registered")]
    [InlineData(SmsSendEligibility.NotAdmitted, "not_admitted")]
    [InlineData(SmsSendEligibility.AdmissionInactive, "admission_inactive")]
    [InlineData(SmsSendEligibility.NotAdminApproved, "not_admin_approved")]
    [InlineData(SmsSendEligibility.AccountDisabled, "account_disabled")]
    public async Task AnIneligiblePhone_IsSuppressedWithoutReachingTheOtpService(
        SmsSendEligibility decision, string reason)
    {
        var accountId = decision == SmsSendEligibility.NotRegistered ? (Guid?)null : Guid.NewGuid();
        GivenEligibility(decision, accountId);

        var outcome = await CreateService().SendAsync(Request(), TestContext.Current.CancellationToken);

        Assert.Equal(reason, outcome);
        Assert.Equal(["count:1", "eligibility"], _calls);
        _otp.VerifyNoOtherCalls();
        AssertAudit(Assert.Single(await HistoriesAsync()), OidcSmsCodeSendService.SuppressedEventType, reason, accountId);
    }

    [Theory]
    [InlineData(OtpSendOutcome.Locked, "otp_locked")]
    [InlineData(OtpSendOutcome.ResendInterval, "resend_interval")]
    [InlineData(OtpSendOutcome.HourlyWindow, "hourly_window")]
    [InlineData(OtpSendOutcome.DailyWindow, "daily_window")]
    [InlineData(OtpSendOutcome.ProfileMissing, "profile_missing")]
    [InlineData(OtpSendOutcome.ProviderFailed, "provider_failed")]
    public async Task AnAbsorbedOtpOutcome_IsSuppressedWithItsClosedReason(OtpSendOutcome delivery, string reason)
    {
        var accountId = Guid.NewGuid();
        GivenEligibility(SmsSendEligibility.Eligible, accountId);
        GivenDelivery(delivery, stageTrackedEntity: true);

        var outcome = await CreateService().SendAsync(Request(), TestContext.Current.CancellationToken);

        Assert.Equal(reason, outcome);
        Assert.Equal(["count:1", "eligibility", "otp"], _calls);
        AssertAudit(Assert.Single(await HistoriesAsync()), OidcSmsCodeSendService.SuppressedEventType, reason, accountId);
        // Whatever the OTP service left tracked never rides along with the suppressed audit row.
        Assert.Empty(await _context.Otps.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ADeliveredCode_CommitsTheStagedStateAndOneSentRow()
    {
        GivenEligibility(SmsSendEligibility.Eligible, accountId: null);
        GivenDelivery(OtpSendOutcome.Sent, stageTrackedEntity: true);

        var outcome = await CreateService().SendAsync(Request(), TestContext.Current.CancellationToken);

        Assert.Equal(OidcSmsCodeSendOutcomes.Sent, outcome);
        AssertAudit(Assert.Single(await HistoriesAsync()), OidcSmsCodeSendService.SentEventType, failureReason: null, accountId: null);
        // The staged delivery state commits in the same unit as the audit row.
        Assert.Single(await _context.Otps.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AFailedReadAfterTheCount_IsPersistenceFailed_WithNoAuditAndTheSlotKept()
    {
        _admissions.Setup(service => service.EvaluateSendEligibilityAsync(
                _applicationId, SmsLoginMode.ManualApproval, Phone, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("database-canary"));

        var outcome = await CreateService().SendAsync(Request(), TestContext.Current.CancellationToken);

        Assert.Equal(OidcSmsCodeSendOutcomes.PersistenceFailed, outcome);
        Assert.Empty(await HistoriesAsync());
        Assert.Equal(1, await CountAsync());
    }

    [Theory]
    [InlineData(OtpSendOutcome.Sent)]
    [InlineData(OtpSendOutcome.ProviderFailed)]
    public async Task AFailedAuditCommit_IsPersistenceFailed(OtpSendOutcome delivery)
    {
        GivenEligibility(SmsSendEligibility.Eligible, Guid.NewGuid());
        GivenDelivery(delivery, stageTrackedEntity: false);
        var audit = new Mock<IAuditService>();
        audit.Setup(service => service.RecordLoginAsync(
                It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new DbUpdateException("audit-canary"));

        var outcome = await CreateService(audit.Object).SendAsync(Request(), TestContext.Current.CancellationToken);

        Assert.Equal(OidcSmsCodeSendOutcomes.PersistenceFailed, outcome);
        Assert.Empty(await HistoriesAsync());
        Assert.Equal(1, await CountAsync());
    }

    [Fact]
    public async Task CancellationBeforeTheCount_WritesNothing()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CreateService().SendAsync(Request(), cancellation.Token));

        Assert.Equal(0, await CountAsync());
        Assert.Empty(await HistoriesAsync());
        _admissions.VerifyNoOtherCalls();
        _otp.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("eligibility")]
    [InlineData("otp")]
    public async Task CancellationAfterTheCount_KeepsTheSlot_AndWritesNothingElse(string boundary)
    {
        using var cancellation = new CancellationTokenSource();
        if (boundary == "eligibility")
        {
            _admissions.Setup(service => service.EvaluateSendEligibilityAsync(
                    _applicationId, SmsLoginMode.ManualApproval, Phone, cancellation.Token))
                .Returns(async () =>
                {
                    await cancellation.CancelAsync();
                    cancellation.Token.ThrowIfCancellationRequested();
                    return new SmsSendEligibilityResult(SmsSendEligibility.Eligible, null);
                });
        }
        else
        {
            GivenEligibility(SmsSendEligibility.Eligible, null);
            _otp.Setup(service => service.TrySendAsync(_applicationId, Phone, "test", cancellation.Token))
                .Returns(async () =>
                {
                    await cancellation.CancelAsync();
                    cancellation.Token.ThrowIfCancellationRequested();
                    return OtpSendOutcome.Sent;
                });
        }

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CreateService().SendAsync(Request(), cancellation.Token));

        Assert.Equal(1, await CountAsync());
        Assert.Empty(await HistoriesAsync());
    }

    private OidcSmsCodeSendService CreateService(IAuditService? audit = null)
    {
        var recordingStore = new Mock<IAuthorizationRequestStore>(MockBehavior.Strict);
        recordingStore.Setup(store => store.TryTakeSmsCodeSendSlotAsync(
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Returns(async (string handle, DateTimeOffset now, CancellationToken token) =>
            {
                var taken = await _store.TryTakeSmsCodeSendSlotAsync(handle, now, token);
                _calls.Add("count:" + (taken ? 1 : 0));
                return taken;
            });
        return new OidcSmsCodeSendService(
            recordingStore.Object,
            _admissions.Object,
            _otp.Object,
            audit ?? new AuditService(new LoginHistoryRepository(_context)),
            new EfCoreUnitOfWork(_context),
            _context,
            NullLogger<OidcSmsCodeSendService>.Instance);
    }

    private OidcSmsCodeSendRequest Request() => new(
        _handle,
        _applicationId,
        AppId,
        SmsLoginMode.ManualApproval,
        "test",
        Phone,
        "203.0.113.7",
        "unit-agent",
        CorrelationId,
        DateTimeOffset.UtcNow);

    private void GivenEligibility(SmsSendEligibility decision, Guid? accountId) =>
        _admissions.Setup(service => service.EvaluateSendEligibilityAsync(
                _applicationId, SmsLoginMode.ManualApproval, Phone, It.IsAny<CancellationToken>()))
            .Callback(() => _calls.Add("eligibility"))
            .ReturnsAsync(new SmsSendEligibilityResult(decision, accountId));

    private void GivenDelivery(OtpSendOutcome delivery, bool stageTrackedEntity) =>
        _otp.Setup(service => service.TrySendAsync(_applicationId, Phone, "test", It.IsAny<CancellationToken>()))
            .Callback(() =>
            {
                _calls.Add("otp");
                if (stageTrackedEntity)
                {
                    // What the OTP service leaves tracked: the staged Sent state on success, or an
                    // unsaved pre-delivery entity after a failed write.
                    _context.Otps.Add(new OtpEntity
                    {
                        Id = Guid.NewGuid(),
                        AppRegistrationId = _applicationId,
                        Phone = Phone,
                        CodeMac = new string('A', 64),
                        Status = OtpStatus.Sent
                    });
                }
            })
            .ReturnsAsync(delivery);

    private async Task SetCountAsync(int count)
    {
        await _context.AuthorizationRequests
            .Where(row => row.Id == _continuationId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SmsCodeSendCount, count),
                TestContext.Current.CancellationToken);
    }

    private async Task<int> CountAsync() =>
        await _context.AuthorizationRequests.AsNoTracking()
            .Where(row => row.Id == _continuationId)
            .Select(row => row.SmsCodeSendCount)
            .SingleAsync(TestContext.Current.CancellationToken);

    private async Task<List<LoginHistoryEntity>> HistoriesAsync() =>
        await _context.LoginHistories.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken);

    private static void AssertAudit(LoginHistoryEntity row, string eventType, string? failureReason, Guid? accountId)
    {
        Assert.Equal(OidcSmsCodeSendService.AuthMethod, row.AuthMethod);
        Assert.Equal(eventType, row.EventType);
        Assert.Equal(failureReason, row.FailureReason);
        Assert.Equal(accountId, row.AccountId);
        Assert.Equal(MaskedPhone, row.Username);
        Assert.Equal(AppId, row.AppId);
        Assert.Equal(CorrelationId, row.CorrelationId);
        Assert.Equal("203.0.113.7", row.ClientIp);
    }
}
