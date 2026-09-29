using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services.Sms;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

/// <summary>
/// The browser SMS send eligibility of <see cref="SmsAdmissionService"/> (#444): the fixed check
/// order decides when several conditions hold at once, <c>AutoProvision</c> admits a phone without
/// an identity or admission, the decision is read-only, and only the phone's SMS identity counts.
/// </summary>
public sealed class SmsSendEligibilityTests : IAsyncLifetime
{
    private const string Phone = "+8613912345678";

    private SqliteConnection _connection = null!;
    private IdentityDbContext _context = null!;
    private Guid _appId;
    private Guid _otherAppId;

    public async ValueTask InitializeAsync()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        await _connection.OpenAsync(TestContext.Current.CancellationToken);
        _context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(_connection).Options);
        await _context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        _appId = await AddApplicationAsync("eligibility-app");
        _otherAppId = await AddApplicationAsync("eligibility-other-app");
    }

    public async ValueTask DisposeAsync()
    {
        await _context.DisposeAsync();
        await _connection.DisposeAsync();
    }

    public enum Identity
    {
        None,
        Active,
        Disabled
    }

    public enum Admission
    {
        None,
        ActiveAdmin,
        ActiveAutoProvision,
        ActiveExchangeGranted,
        InactiveAdmin,
        InactiveAutoProvision,
        OtherApplicationOnly
    }

    /// <summary>
    /// Every identity × admission combination under both enabled modes. The first failing check in
    /// the order identity → account → admission row → admission active → Admin approval decides.
    /// </summary>
    [Theory]
    [InlineData(SmsLoginMode.ManualApproval, Identity.None, Admission.None, SmsSendEligibility.NotRegistered)]
    [InlineData(SmsLoginMode.AutoProvision, Identity.None, Admission.None, SmsSendEligibility.Eligible)]
    // A disabled account precedes every admission condition.
    [InlineData(SmsLoginMode.ManualApproval, Identity.Disabled, Admission.None, SmsSendEligibility.AccountDisabled)]
    [InlineData(SmsLoginMode.AutoProvision, Identity.Disabled, Admission.None, SmsSendEligibility.AccountDisabled)]
    [InlineData(SmsLoginMode.ManualApproval, Identity.Disabled, Admission.InactiveAutoProvision, SmsSendEligibility.AccountDisabled)]
    [InlineData(SmsLoginMode.ManualApproval, Identity.Disabled, Admission.ActiveAdmin, SmsSendEligibility.AccountDisabled)]
    [InlineData(SmsLoginMode.AutoProvision, Identity.Disabled, Admission.ActiveAdmin, SmsSendEligibility.AccountDisabled)]
    // No admission row for this application.
    [InlineData(SmsLoginMode.ManualApproval, Identity.Active, Admission.None, SmsSendEligibility.NotAdmitted)]
    [InlineData(SmsLoginMode.AutoProvision, Identity.Active, Admission.None, SmsSendEligibility.Eligible)]
    [InlineData(SmsLoginMode.ManualApproval, Identity.Active, Admission.OtherApplicationOnly, SmsSendEligibility.NotAdmitted)]
    [InlineData(SmsLoginMode.AutoProvision, Identity.Active, Admission.OtherApplicationOnly, SmsSendEligibility.Eligible)]
    // An inactive admission precedes the Admin-approval check and is never eligible.
    [InlineData(SmsLoginMode.ManualApproval, Identity.Active, Admission.InactiveAutoProvision, SmsSendEligibility.AdmissionInactive)]
    [InlineData(SmsLoginMode.ManualApproval, Identity.Active, Admission.InactiveAdmin, SmsSendEligibility.AdmissionInactive)]
    [InlineData(SmsLoginMode.AutoProvision, Identity.Active, Admission.InactiveAdmin, SmsSendEligibility.AdmissionInactive)]
    [InlineData(SmsLoginMode.AutoProvision, Identity.Active, Admission.InactiveAutoProvision, SmsSendEligibility.AdmissionInactive)]
    // Under ManualApproval only an Admin-approved admission is eligible.
    [InlineData(SmsLoginMode.ManualApproval, Identity.Active, Admission.ActiveAutoProvision, SmsSendEligibility.NotAdminApproved)]
    [InlineData(SmsLoginMode.ManualApproval, Identity.Active, Admission.ActiveExchangeGranted, SmsSendEligibility.NotAdminApproved)]
    [InlineData(SmsLoginMode.ManualApproval, Identity.Active, Admission.ActiveAdmin, SmsSendEligibility.Eligible)]
    [InlineData(SmsLoginMode.AutoProvision, Identity.Active, Admission.ActiveAutoProvision, SmsSendEligibility.Eligible)]
    [InlineData(SmsLoginMode.AutoProvision, Identity.Active, Admission.ActiveExchangeGranted, SmsSendEligibility.Eligible)]
    [InlineData(SmsLoginMode.AutoProvision, Identity.Active, Admission.ActiveAdmin, SmsSendEligibility.Eligible)]
    public async Task TheFirstFailingCheckDecides(
        SmsLoginMode mode,
        Identity identity,
        Admission admission,
        SmsSendEligibility expected)
    {
        var accountId = await SeedAsync(identity, admission);
        var before = await SnapshotAsync();

        var result = await new SmsAdmissionService(_context).EvaluateSendEligibilityAsync(
            _appId, mode, "139 1234 5678", TestContext.Current.CancellationToken);

        Assert.Equal(expected, result.Decision);
        // The account id travels only when an SMS identity resolved (for the masked audit row).
        Assert.Equal(accountId, result.AccountId);
        // Read-only: nothing tracked, nothing written, nothing provisioned.
        Assert.Empty(_context.ChangeTracker.Entries());
        Assert.Equal(before, await SnapshotAsync());
    }

    [Fact]
    public async Task AnotherProvidersIdentityWithTheSameValue_IsNotAnSmsIdentity()
    {
        var accountId = Guid.NewGuid();
        _context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
        _context.UserLogins.Add(new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            ProviderName = "WeChat",
            ProviderUserId = Phone
        });
        await _context.SaveChangesAsync(TestContext.Current.CancellationToken);
        _context.ChangeTracker.Clear();

        var result = await new SmsAdmissionService(_context).EvaluateSendEligibilityAsync(
            _appId, SmsLoginMode.ManualApproval, Phone, TestContext.Current.CancellationToken);

        Assert.Equal(SmsSendEligibility.NotRegistered, result.Decision);
        Assert.Null(result.AccountId);
    }

    [Fact]
    public async Task ADisabledMode_IsAProgrammingError()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            new SmsAdmissionService(_context).EvaluateSendEligibilityAsync(
                _appId, SmsLoginMode.Disabled, Phone, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ACancelledRead_Propagates()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new SmsAdmissionService(_context).EvaluateSendEligibilityAsync(
                _appId, SmsLoginMode.ManualApproval, Phone, cancellation.Token));
    }

    private async Task<Guid?> SeedAsync(Identity identity, Admission admission)
    {
        if (identity == Identity.None)
        {
            return null;
        }

        var accountId = Guid.NewGuid();
        var loginId = Guid.NewGuid();
        _context.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = identity == Identity.Active,
            CreatedAt = DateTimeOffset.UtcNow
        });
        _context.UserLogins.Add(new UserLoginEntity
        {
            Id = loginId,
            AccountId = accountId,
            ProviderName = IdentityConstants.AuthMethodSms,
            ProviderUserId = Phone
        });

        var (applicationId, source, active) = admission switch
        {
            Admission.ActiveAdmin => (_appId, SmsAccessApprovalSource.Admin, true),
            Admission.ActiveAutoProvision => (_appId, SmsAccessApprovalSource.AutoProvision, true),
            Admission.ActiveExchangeGranted => (_appId, SmsAccessApprovalSource.ExchangeGranted, true),
            Admission.InactiveAdmin => (_appId, SmsAccessApprovalSource.Admin, false),
            Admission.InactiveAutoProvision => (_appId, SmsAccessApprovalSource.AutoProvision, false),
            Admission.OtherApplicationOnly => (_otherAppId, SmsAccessApprovalSource.Admin, true),
            _ => (Guid.Empty, default, false)
        };
        if (applicationId != Guid.Empty)
        {
            _context.AppSmsAccesses.Add(new AppSmsAccessEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = applicationId,
                UserLoginId = loginId,
                ApprovalSource = source,
                IsActive = active,
                CreatedAt = DateTimeOffset.UtcNow
            });
        }

        await _context.SaveChangesAsync(TestContext.Current.CancellationToken);
        _context.ChangeTracker.Clear();
        return accountId;
    }

    private async Task<string> SnapshotAsync()
    {
        var accounts = await _context.Accounts.AsNoTracking().OrderBy(row => row.Id)
            .Select(row => row.Id + ":" + row.IsActive).ToListAsync(TestContext.Current.CancellationToken);
        var logins = await _context.UserLogins.AsNoTracking().OrderBy(row => row.Id)
            .Select(row => row.Id + ":" + row.ProviderUserId).ToListAsync(TestContext.Current.CancellationToken);
        var accesses = await _context.AppSmsAccesses.AsNoTracking().OrderBy(row => row.Id)
            .Select(row => row.Id + ":" + row.IsActive + ":" + row.ApprovalSource)
            .ToListAsync(TestContext.Current.CancellationToken);
        return string.Join('|', accounts.Concat(logins).Concat(accesses));
    }

    private async Task<Guid> AddApplicationAsync(string appId)
    {
        var id = Guid.NewGuid();
        _context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = id,
            AppId = appId,
            AppName = appId,
            AppSecretHash = "unused-test-hash",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await _context.SaveChangesAsync(TestContext.Current.CancellationToken);
        _context.ChangeTracker.Clear();
        return id;
    }
}
