using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services.Sms;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

/// <summary>
/// The read-only <c>PS-04</c> SMS admission predicate of an <c>Sms</c> identity session
/// (<see cref="SmsAdmissionService.IsSessionAdmittedAsync"/>, <c>EV-38</c>): the current mode,
/// the admission row of this application and this SMS login identity, its active flag, and the
/// Admin approval under <c>ManualApproval</c>. The predicate never writes, never provisions, and
/// is independent of the SMS profile key. Also covers the <c>PS-12</c> "exactly one Password
/// credential" name source of an <c>Sms</c> session.
/// </summary>
public sealed class SmsSessionAdmissionPredicateTests : IAsyncLifetime
{
    private SqliteConnection _connection = null!;
    private IdentityDbContext _context = null!;
    private Guid _appId;
    private Guid _otherAppId;
    private Guid _accountId;
    private Guid _loginId;

    public async ValueTask InitializeAsync()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        await _connection.OpenAsync(TestContext.Current.CancellationToken);
        _context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(_connection).Options);
        await _context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        _appId = await AddApplicationAsync("predicate-app");
        _otherAppId = await AddApplicationAsync("predicate-other-app");
        _accountId = Guid.NewGuid();
        _loginId = Guid.NewGuid();
        _context.Accounts.Add(new AccountEntity { Id = _accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
        _context.UserLogins.Add(new UserLoginEntity
        {
            Id = _loginId,
            AccountId = _accountId,
            ProviderName = IdentityConstants.AuthMethodSms,
            ProviderUserId = "+8613912345678"
        });
        await _context.SaveChangesAsync(TestContext.Current.CancellationToken);
        _context.ChangeTracker.Clear();
    }

    public async ValueTask DisposeAsync()
    {
        await _context.DisposeAsync();
        await _connection.DisposeAsync();
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

    [Theory]
    // SMS disabled: false whatever the admission says.
    [InlineData(SmsLoginMode.Disabled, Admission.ActiveAdmin, false)]
    [InlineData(SmsLoginMode.Disabled, Admission.ActiveAutoProvision, false)]
    // ManualApproval: only an active Admin-approved admission of this application.
    [InlineData(SmsLoginMode.ManualApproval, Admission.ActiveAdmin, true)]
    [InlineData(SmsLoginMode.ManualApproval, Admission.ActiveAutoProvision, false)]
    [InlineData(SmsLoginMode.ManualApproval, Admission.ActiveExchangeGranted, false)]
    [InlineData(SmsLoginMode.ManualApproval, Admission.InactiveAdmin, false)]
    [InlineData(SmsLoginMode.ManualApproval, Admission.None, false)]
    [InlineData(SmsLoginMode.ManualApproval, Admission.OtherApplicationOnly, false)]
    // AutoProvision: any active admission row, but a missing row is never provisioned on reuse.
    [InlineData(SmsLoginMode.AutoProvision, Admission.ActiveAdmin, true)]
    [InlineData(SmsLoginMode.AutoProvision, Admission.ActiveAutoProvision, true)]
    [InlineData(SmsLoginMode.AutoProvision, Admission.ActiveExchangeGranted, true)]
    [InlineData(SmsLoginMode.AutoProvision, Admission.InactiveAutoProvision, false)]
    [InlineData(SmsLoginMode.AutoProvision, Admission.None, false)]
    [InlineData(SmsLoginMode.AutoProvision, Admission.OtherApplicationOnly, false)]
    public async Task IsSessionAdmittedAsync_FollowsThePs04Predicate(
        SmsLoginMode mode,
        Admission admission,
        bool expected)
    {
        await SeedAdmissionAsync(admission);
        var before = await SnapshotAsync();

        var admitted = await new SmsAdmissionService(_context).IsSessionAdmittedAsync(
            _appId, mode, _loginId, TestContext.Current.CancellationToken);

        Assert.Equal(expected, admitted);
        // Read-only: no admission, identity, or account row appears or changes, and nothing is tracked.
        Assert.Equal(before, await SnapshotAsync());
        Assert.Empty(_context.ChangeTracker.Entries());
    }

    [Fact]
    public async Task IsSessionAdmittedAsync_ObservesAPreCanceledToken()
    {
        await SeedAdmissionAsync(Admission.ActiveAdmin);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new SmsAdmissionService(_context).IsSessionAdmittedAsync(
                _appId, SmsLoginMode.ManualApproval, _loginId, new CancellationToken(canceled: true)));
    }

    [Theory]
    [InlineData(0, null)]
    [InlineData(1, "sole_user_0")]
    [InlineData(2, null)]
    public async Task GetSoleUsernameByAccountIdAsync_ReturnsTheUsernameOnlyForExactlyOneCredential(
        int credentialCount,
        string? expected)
    {
        for (var index = 0; index < credentialCount; index++)
        {
            _context.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = Guid.NewGuid(),
                AccountId = _accountId,
                Username = $"sole_user_{index}",
                PasswordHash = "hash",
                CreatedAt = DateTimeOffset.UtcNow
            });
        }

        // Another account's credential never counts.
        var otherAccountId = Guid.NewGuid();
        _context.Accounts.Add(new AccountEntity { Id = otherAccountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
        _context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = otherAccountId,
            Username = "other_account_user",
            PasswordHash = "hash",
            CreatedAt = DateTimeOffset.UtcNow
        });
        await _context.SaveChangesAsync(TestContext.Current.CancellationToken);
        _context.ChangeTracker.Clear();

        var username = await new PasswordCredentialRepository(_context)
            .GetSoleUsernameByAccountIdAsync(_accountId, TestContext.Current.CancellationToken);

        Assert.Equal(expected, username);
    }

    private async Task SeedAdmissionAsync(Admission admission)
    {
        (Guid App, SmsAccessApprovalSource Source, bool Active)? row = admission switch
        {
            Admission.None => null,
            Admission.ActiveAdmin => (_appId, SmsAccessApprovalSource.Admin, true),
            Admission.ActiveAutoProvision => (_appId, SmsAccessApprovalSource.AutoProvision, true),
            Admission.ActiveExchangeGranted => (_appId, SmsAccessApprovalSource.ExchangeGranted, true),
            Admission.InactiveAdmin => (_appId, SmsAccessApprovalSource.Admin, false),
            Admission.InactiveAutoProvision => (_appId, SmsAccessApprovalSource.AutoProvision, false),
            Admission.OtherApplicationOnly => (_otherAppId, SmsAccessApprovalSource.Admin, true),
            _ => throw new ArgumentOutOfRangeException(nameof(admission))
        };
        if (row is { } value)
        {
            _context.AppSmsAccesses.Add(new AppSmsAccessEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = value.App,
                UserLoginId = _loginId,
                ApprovalSource = value.Source,
                IsActive = value.Active,
                CreatedAt = DateTimeOffset.UtcNow
            });
            await _context.SaveChangesAsync(TestContext.Current.CancellationToken);
            _context.ChangeTracker.Clear();
        }
    }

    private async Task<string> SnapshotAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var accesses = await _context.AppSmsAccesses.AsNoTracking()
            .OrderBy(row => row.Id)
            .Select(row => $"{row.Id}:{row.AppRegistrationId}:{row.UserLoginId}:{row.ApprovalSource}:{row.IsActive}")
            .ToListAsync(ct);
        var logins = await _context.UserLogins.AsNoTracking().CountAsync(ct);
        var accounts = await _context.Accounts.AsNoTracking().CountAsync(ct);
        return $"{string.Join('|', accesses)}#{logins}#{accounts}";
    }

    private async Task<Guid> AddApplicationAsync(string appId)
    {
        var id = Guid.NewGuid();
        _context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = id,
            AppId = appId,
            AppSecretHash = "hash",
            AppName = appId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await _context.SaveChangesAsync(TestContext.Current.CancellationToken);
        _context.ChangeTracker.Clear();
        return id;
    }
}
