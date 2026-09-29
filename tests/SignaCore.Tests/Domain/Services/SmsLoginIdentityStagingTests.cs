using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services.Sms;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

/// <summary>
/// The in-transaction identity resolution of the browser SMS login
/// (<see cref="SmsAdmissionService.FindOrStageLoginIdentityAsync"/>, #445, <c>EV-36</c> step 3): it
/// requires the caller's transaction, never saves, stages under <c>AutoProvision</c> exactly what is
/// missing, never changes an existing admission, stages nothing for a disabled account, and under
/// <c>ManualApproval</c> only reads.
/// </summary>
public sealed class SmsLoginIdentityStagingTests : IAsyncLifetime
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
        _appId = await AddApplicationAsync("staging-app");
        _otherAppId = await AddApplicationAsync("staging-other-app");
    }

    public async ValueTask DisposeAsync()
    {
        await _context.DisposeAsync();
        await _connection.DisposeAsync();
    }

    [Fact]
    public async Task WithoutTheCallersTransaction_Throws()
    {
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new SmsAdmissionService(_context).FindOrStageLoginIdentityAsync(
                _appId, SmsLoginMode.AutoProvision, Phone, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));
        Assert.DoesNotContain(Phone, exception.Message, StringComparison.Ordinal);
        Assert.Empty(_context.ChangeTracker.Entries());
    }

    [Fact]
    public async Task AutoProvision_WithoutAnIdentity_StagesAccountIdentityAndAdmission_WithoutSaving()
    {
        var now = DateTimeOffset.UtcNow;
        await using var transaction = await _context.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);

        var identity = await new SmsAdmissionService(_context).FindOrStageLoginIdentityAsync(
            _appId, SmsLoginMode.AutoProvision, "139 1234 5678", now, TestContext.Current.CancellationToken);

        Assert.NotNull(identity);
        Assert.True(identity.AccountCreated);
        var added = _context.ChangeTracker.Entries().Where(entry => entry.State == EntityState.Added).ToList();
        Assert.Equal(3, added.Count);
        var account = Assert.Single(added.Select(entry => entry.Entity).OfType<AccountEntity>());
        Assert.Equal((identity.AccountId, true, now), (account.Id, account.IsActive, account.CreatedAt));
        var login = Assert.Single(added.Select(entry => entry.Entity).OfType<UserLoginEntity>());
        Assert.Equal((identity.UserLoginId, account.Id, IdentityConstants.AuthMethodSms, Phone),
            (login.Id, login.AccountId, login.ProviderName, login.ProviderUserId));
        var access = Assert.Single(added.Select(entry => entry.Entity).OfType<AppSmsAccessEntity>());
        Assert.Equal((_appId, login.Id, SmsAccessApprovalSource.AutoProvision, true, (Guid?)null),
            (access.AppRegistrationId, access.UserLoginId, access.ApprovalSource, access.IsActive, access.ApprovedBy));

        // Nothing reached the database: the rows belong to the caller's unit.
        Assert.Equal(0, await _context.UserLogins.AsNoTracking().CountAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, await _context.AppSmsAccesses.AsNoTracking().CountAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AutoProvision_ForAnIdentityOfAnotherApplication_StagesOnlyTheAdmission()
    {
        var (accountId, loginId) = await SeedIdentityAsync(accountActive: true, (_otherAppId, true));
        await using var transaction = await _context.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);

        var identity = await new SmsAdmissionService(_context).FindOrStageLoginIdentityAsync(
            _appId, SmsLoginMode.AutoProvision, Phone, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);

        Assert.Equal(new SmsLoginIdentity(accountId, loginId, AccountCreated: false), identity);
        var added = Assert.Single(_context.ChangeTracker.Entries().Where(entry => entry.State == EntityState.Added));
        var access = Assert.IsType<AppSmsAccessEntity>(added.Entity);
        Assert.Equal((_appId, loginId, SmsAccessApprovalSource.AutoProvision), (access.AppRegistrationId, access.UserLoginId, access.ApprovalSource));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AutoProvision_NeverChangesAnExistingAdmission(bool active)
    {
        var (accountId, loginId) = await SeedIdentityAsync(accountActive: true, (_appId, active));
        await using var transaction = await _context.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);

        var identity = await new SmsAdmissionService(_context).FindOrStageLoginIdentityAsync(
            _appId, SmsLoginMode.AutoProvision, Phone, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);

        Assert.Equal(new SmsLoginIdentity(accountId, loginId, AccountCreated: false), identity);
        Assert.DoesNotContain(_context.ChangeTracker.Entries(), entry => entry.State is EntityState.Added or EntityState.Modified);
    }

    [Fact]
    public async Task AutoProvision_StagesNothingForADisabledAccount()
    {
        var (accountId, loginId) = await SeedIdentityAsync(accountActive: false, admission: null);
        await using var transaction = await _context.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);

        var identity = await new SmsAdmissionService(_context).FindOrStageLoginIdentityAsync(
            _appId, SmsLoginMode.AutoProvision, Phone, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);

        Assert.Equal(new SmsLoginIdentity(accountId, loginId, AccountCreated: false), identity);
        Assert.DoesNotContain(_context.ChangeTracker.Entries(), entry => entry.State == EntityState.Added);
    }

    [Fact]
    public async Task ManualApproval_OnlyReads()
    {
        var (accountId, loginId) = await SeedIdentityAsync(accountActive: true, admission: null);
        await using var transaction = await _context.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);
        var service = new SmsAdmissionService(_context);

        Assert.Equal(
            new SmsLoginIdentity(accountId, loginId, AccountCreated: false),
            await service.FindOrStageLoginIdentityAsync(
                _appId, SmsLoginMode.ManualApproval, Phone, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));
        Assert.Null(await service.FindOrStageLoginIdentityAsync(
            _appId, SmsLoginMode.ManualApproval, "+8613800000000", DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));
        Assert.DoesNotContain(_context.ChangeTracker.Entries(), entry => entry.State == EntityState.Added);
    }

    [Fact]
    public async Task ADisabledMode_ResolvesNothing()
    {
        await SeedIdentityAsync(accountActive: true, (_appId, true));
        await using var transaction = await _context.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);

        Assert.Null(await new SmsAdmissionService(_context).FindOrStageLoginIdentityAsync(
            _appId, SmsLoginMode.Disabled, Phone, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));
        Assert.DoesNotContain(_context.ChangeTracker.Entries(), entry => entry.State == EntityState.Added);
    }

    [Fact]
    public async Task APreCanceledToken_IsObserved()
    {
        await using var transaction = await _context.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new SmsAdmissionService(_context).FindOrStageLoginIdentityAsync(
                _appId, SmsLoginMode.AutoProvision, Phone, DateTimeOffset.UtcNow, cancellation.Token));
        Assert.Empty(_context.ChangeTracker.Entries());
    }

    private async Task<(Guid AccountId, Guid LoginId)> SeedIdentityAsync(
        bool accountActive,
        (Guid AppId, bool Active)? admission)
    {
        var accountId = Guid.NewGuid();
        var loginId = Guid.NewGuid();
        _context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = accountActive, CreatedAt = DateTimeOffset.UtcNow });
        _context.UserLogins.Add(new UserLoginEntity
        {
            Id = loginId,
            AccountId = accountId,
            ProviderName = IdentityConstants.AuthMethodSms,
            ProviderUserId = Phone
        });
        if (admission is { } row)
        {
            _context.AppSmsAccesses.Add(new AppSmsAccessEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = row.AppId,
                UserLoginId = loginId,
                ApprovalSource = SmsAccessApprovalSource.Admin,
                IsActive = row.Active,
                CreatedAt = DateTimeOffset.UtcNow
            });
        }

        await _context.SaveChangesAsync(TestContext.Current.CancellationToken);
        _context.ChangeTracker.Clear();
        return (accountId, loginId);
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
