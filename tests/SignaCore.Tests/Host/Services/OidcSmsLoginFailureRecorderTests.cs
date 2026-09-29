using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Sms;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Services;

/// <summary>
/// The <c>EV-37</c> failure unit (<see cref="OidcSmsLoginFailureRecorder"/>, #445): the optional
/// conditional OTP failure change and one masked <c>login_failure</c> row commit together, the
/// Password counter is never written, a unit that cannot commit is reduced to one closed log reason
/// without an exception, and caller cancellation still propagates (<c>EV-18</c>).
/// </summary>
public sealed class OidcSmsLoginFailureRecorderTests : IAsyncLifetime
{
    private const string Phone = "+8613912345678";
    private const string MaskedPhone = "+86****5678";
    private const string AppId = "sms-failure-unit-app";
    private const string CorrelationId = "sms-failure-unit-correlation";
    private const string CodeMac = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";

    private readonly List<string> _logs = [];
    private SqliteConnection _connection = null!;
    private IdentityDbContext _context = null!;
    private Guid _applicationId;

    public async ValueTask InitializeAsync()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        await _connection.OpenAsync(TestContext.Current.CancellationToken);
        _context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>().UseSqlite(_connection).Options);
        await _context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        _applicationId = Guid.NewGuid();
        _context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = _applicationId,
            AppId = AppId,
            AppSecretHash = "hash",
            AppName = AppId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        var now = DateTimeOffset.UtcNow;
        _context.Otps.Add(new OtpEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = _applicationId,
            Phone = Phone,
            CodeMac = CodeMac,
            Status = OtpStatus.Sent,
            ExpiresAt = now.AddMinutes(5),
            LockoutUntil = DateTimeOffset.UnixEpoch,
            CreatedAt = now,
            HourWindowStartedAt = now,
            HourSendCount = 1,
            DayWindowStartedAt = now,
            DaySendCount = 1,
            Provider = "fake",
            ProfileKey = "profile",
            Version = 1
        });
        await _context.SaveChangesAsync(TestContext.Current.CancellationToken);
        _context.ChangeTracker.Clear();
    }

    public async ValueTask DisposeAsync()
    {
        await _context.DisposeAsync();
        await _connection.DisposeAsync();
    }

    [Fact]
    public async Task AFailureChange_CommitsWithTheMaskedAudit_AndNeverTouchesThePasswordCounter()
    {
        var accountId = Guid.NewGuid();
        var committed = await Recorder().RecordFailureAsync(
            FailureChange(maxAttempts: 5), Phone, accountId, OidcSmsLoginFailureReasons.OtpRejected, AppId,
            "203.0.113.5", "agent", CorrelationId, TestContext.Current.CancellationToken);

        Assert.True(committed);
        var otp = await _context.Otps.AsNoTracking().SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, otp.Attempts);
        Assert.Equal(DateTimeOffset.UnixEpoch, otp.LockoutUntil);
        var history = Assert.Single(await _context.LoginHistories.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(
            (accountId, MaskedPhone, "oidc_sms_login", "login_failure", "otp_rejected", AppId, CorrelationId),
            ((Guid?)history.AccountId, history.Username, history.AuthMethod, history.EventType, history.FailureReason,
                history.AppId, history.CorrelationId));
        Assert.Empty(await _context.LoginAttempts.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
        Assert.Contains(_logs, line => line.Contains("Reason=otp_rejected", StringComparison.Ordinal));
        Assert.DoesNotContain(_logs, line => line.Contains(Phone, StringComparison.Ordinal) || line.Contains(CodeMac, StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheLastAllowedFailure_LocksTheOtp()
    {
        await Recorder().RecordFailureAsync(
            FailureChange(maxAttempts: 1), Phone, null, OidcSmsLoginFailureReasons.OtpRejected, AppId,
            null, null, CorrelationId, TestContext.Current.CancellationToken);

        var otp = await _context.Otps.AsNoTracking().SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, otp.Attempts);
        Assert.True(otp.LockoutUntil > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task WithoutAChange_OnlyTheAuditCommits_WithoutAnAccountForAnUnresolvedPhone()
    {
        Assert.True(await Recorder().RecordFailureAsync(
            null, Phone, null, "not_registered", AppId, null, null, CorrelationId, TestContext.Current.CancellationToken));

        Assert.Equal(0, (await _context.Otps.AsNoTracking().SingleAsync(TestContext.Current.CancellationToken)).Attempts);
        var history = Assert.Single(await _context.LoginHistories.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
        Assert.Null(history.AccountId);
        Assert.Equal(("not_registered", MaskedPhone), (history.FailureReason, history.Username));
    }

    [Fact]
    public async Task AUnitThatCannotCommit_IsAClosedLogReason_AndNotAnException()
    {
        var recorder = Recorder(new ThrowingAuditService());

        var committed = await recorder.RecordFailureAsync(
            FailureChange(maxAttempts: 5), Phone, null, OidcSmsLoginFailureReasons.OtpRace, AppId,
            null, null, CorrelationId, TestContext.Current.CancellationToken);

        Assert.False(committed);
        Assert.Equal(0, (await _context.Otps.AsNoTracking().SingleAsync(TestContext.Current.CancellationToken)).Attempts);
        Assert.Empty(await _context.LoginHistories.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
        var line = Assert.Single(_logs, entry => entry.Contains("could not persist", StringComparison.Ordinal));
        Assert.Contains("Stage=failure_unit", line, StringComparison.Ordinal);
        Assert.DoesNotContain("Simulated", line, StringComparison.Ordinal);
        Assert.DoesNotContain(Phone, line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallerCancellation_Propagates_AndWritesNothing()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Recorder().RecordFailureAsync(
            FailureChange(maxAttempts: 5), Phone, null, OidcSmsLoginFailureReasons.OtpRejected, AppId,
            null, null, CorrelationId, cancellation.Token));

        Assert.Equal(0, (await _context.Otps.AsNoTracking().SingleAsync(TestContext.Current.CancellationToken)).Attempts);
        Assert.Empty(await _context.LoginHistories.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AConsumption_IsRejectedBeforeAnyWrite()
    {
        var consume = FailureChange(maxAttempts: 5) with { Kind = OtpVerificationChangeKind.Consume };

        await Assert.ThrowsAsync<ArgumentException>(() => Recorder().RecordFailureAsync(
            consume, Phone, null, OidcSmsLoginFailureReasons.OtpRejected, AppId, null, null, CorrelationId,
            TestContext.Current.CancellationToken));

        Assert.Equal(OtpStatus.Sent, (await _context.Otps.AsNoTracking().SingleAsync(TestContext.Current.CancellationToken)).Status);
        Assert.Empty(await _context.LoginHistories.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
    }

    private OidcSmsLoginFailureRecorder Recorder(IAuditService? audit = null) => new(
        new OtpRepository(_context),
        audit ?? new AuditService(new LoginHistoryRepository(_context)),
        new EfCoreUnitOfWork(_context),
        _context,
        new ListLogger(_logs));

    private OtpVerificationChange FailureChange(int maxAttempts) => new(
        OtpVerificationChangeKind.RecordFailure,
        _applicationId,
        Phone,
        CodeMac,
        DateTimeOffset.UtcNow,
        maxAttempts,
        DateTimeOffset.UtcNow.AddMinutes(15));

    private sealed class ThrowingAuditService : IAuditService
    {
        public Task RecordLoginAsync(Guid? accountId, string username, string authMethod, string eventType,
            string? clientIp, string? userAgent, string? failureReason = null, string? appId = null,
            string? correlationId = null, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Simulated audit persistence failure.");
    }

    private sealed class ListLogger(List<string> messages) : ILogger<OidcSmsLoginFailureRecorder>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => messages.Add(formatter(state, exception));
    }
}
