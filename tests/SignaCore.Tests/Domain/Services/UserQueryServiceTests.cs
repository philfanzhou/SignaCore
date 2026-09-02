using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class UserQueryServiceTests : IDisposable
{
    private readonly IdentityDbContext _dbContext;
    private readonly UserQueryService _service;

    public UserQueryServiceTests()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        _dbContext = new IdentityDbContext(options);
        _service = new UserQueryService(_dbContext);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    private AccountEntity SeedAccount(string? nickname = null, string? remark = null, bool isActive = true)
    {
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            Nickname = nickname,
            Remark = remark,
            IsActive = isActive,
            CreatedAt = DateTimeOffset.UtcNow
        };
        _dbContext.Accounts.Add(account);
        _dbContext.SaveChanges();
        return account;
    }

    private void SeedPasswordCredential(Guid accountId, string username)
    {
        _dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = username,
            PasswordHash = "hash",
            CreatedAt = DateTimeOffset.UtcNow
        });
        _dbContext.SaveChanges();
    }

    private void SeedSmsLogin(Guid accountId, string phone)
    {
        _dbContext.UserLogins.Add(new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            ProviderName = IdentityConstants.AuthMethodSms,
            ProviderUserId = phone
        });
        _dbContext.SaveChanges();
    }

    [Fact]
    public async Task SearchUsersAsync_NoFilter_ReturnsAllPaged()
    {
        SeedAccount();
        SeedAccount();
        SeedAccount();

        var (users, total) = await _service.SearchUsersAsync(null, null, 1, 20);

        Assert.Equal(3, total);
        Assert.Equal(3, users.Count);
    }

    [Fact]
    public async Task SearchUsersAsync_WithCanceledToken_ThrowsOperationCanceledException()
    {
        SeedAccount();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _service.SearchUsersAsync(null, null, 1, 20, cancellation.Token));
    }

    [Fact]
    public async Task SearchUsersAsync_UsernameFilter_MatchesCredentialUsername()
    {
        var account = SeedAccount();
        SeedPasswordCredential(account.Id, "alice");
        var other = SeedAccount();
        SeedPasswordCredential(other.Id, "bob");

        var (users, total) = await _service.SearchUsersAsync("ali", null, 1, 20);

        Assert.Equal(1, total);
        Assert.Equal("alice", users[0].Username);
    }

    [Fact]
    public async Task SearchUsersAsync_UsernameFilter_MatchesRemark()
    {
        SeedAccount(remark: "VIP customer");
        SeedAccount(remark: "regular");

        var (users, total) = await _service.SearchUsersAsync("VIP", null, 1, 20);

        Assert.Equal(1, total);
    }

    [Fact]
    public async Task SearchUsersAsync_PhoneFilter_MatchesSmsLogin()
    {
        var account = SeedAccount();
        SeedSmsLogin(account.Id, "13800001234");
        SeedAccount();

        var (users, total) = await _service.SearchUsersAsync(null, "1380000", 1, 20);

        Assert.Equal(1, total);
        Assert.Equal("13800001234", users[0].Phone);
    }

    [Fact]
    public async Task SearchUsersAsync_Paging_ReturnsCorrectSlice()
    {
        for (var i = 0; i < 5; i++)
        {
            SeedAccount();
        }

        var (page1, total) = await _service.SearchUsersAsync(null, null, 1, 2);
        var (page2, _) = await _service.SearchUsersAsync(null, null, 2, 2);

        Assert.Equal(5, total);
        Assert.Equal(2, page1.Count);
        Assert.Equal(2, page2.Count);
        Assert.NotEqual(page1[0].UserId, page2[0].UserId);
    }

    [Fact]
    public async Task SearchUsersAsync_HasPassword_ReflectsPasswordCredential()
    {
        var passwordAccount = SeedAccount();
        SeedPasswordCredential(passwordAccount.Id, "alice");
        var phoneAccount = SeedAccount();
        SeedSmsLogin(phoneAccount.Id, "13800001234");

        var (users, _) = await _service.SearchUsersAsync(null, null, 1, 20);

        var passwordItem = Assert.Single(users, u => u.UserId == passwordAccount.Id.ToString());
        Assert.True(passwordItem.HasPassword);
        var phoneItem = Assert.Single(users, u => u.UserId == phoneAccount.Id.ToString());
        Assert.False(phoneItem.HasPassword);
        // Phone-only accounts fall back to the phone number as Username; type must not be derived from it.
        Assert.Equal("13800001234", phoneItem.Username);
    }

    [Fact]
    public async Task SearchUsersAsync_DisplayName_FallsBackThroughNicknameUsernamePhoneId()
    {
        var withNickname = SeedAccount(nickname: "Nick");
        SeedPasswordCredential(withNickname.Id, "alice");
        var withUsername = SeedAccount();
        SeedPasswordCredential(withUsername.Id, "bob");
        var withPhoneOnly = SeedAccount();
        SeedSmsLogin(withPhoneOnly.Id, "13800001234");
        var bare = SeedAccount();

        var (users, _) = await _service.SearchUsersAsync(null, null, 1, 20);

        Assert.Equal("Nick", Assert.Single(users, u => u.UserId == withNickname.Id.ToString()).DisplayName);
        Assert.Equal("bob", Assert.Single(users, u => u.UserId == withUsername.Id.ToString()).DisplayName);
        Assert.Equal("13800001234", Assert.Single(users, u => u.UserId == withPhoneOnly.Id.ToString()).DisplayName);
        Assert.Equal(bare.Id.ToString()[..8], Assert.Single(users, u => u.UserId == bare.Id.ToString()).DisplayName);
    }

    [Fact]
    public async Task GetUsersByIdsAsync_NullOrEmpty_ReturnsEmpty()
    {
        Assert.Empty(await _service.GetUsersByIdsAsync(new List<string>()));
        Assert.Empty(await _service.GetUsersByIdsAsync(new List<string> { " ", "" }));
    }

    [Fact]
    public async Task GetUsersByIdsAsync_InvalidGuids_AreFiltered()
    {
        var account = SeedAccount();

        var users = await _service.GetUsersByIdsAsync(new List<string> { "not-a-guid", account.Id.ToString(), "also-bad" });

        Assert.Single(users);
        Assert.Equal(account.Id.ToString(), users[0].UserId);
    }

    [Fact]
    public async Task GetUsersByIdsAsync_PreservesRequestOrderAndSkipsMissing()
    {
        var a = SeedAccount();
        var b = SeedAccount();
        var c = SeedAccount();

        var users = await _service.GetUsersByIdsAsync(new List<string>
        {
            c.Id.ToString(),
            Guid.NewGuid().ToString(), // missing
            a.Id.ToString(),
            b.Id.ToString()
        });

        Assert.Equal(3, users.Count);
        Assert.Equal(c.Id.ToString(), users[0].UserId);
        Assert.Equal(a.Id.ToString(), users[1].UserId);
        Assert.Equal(b.Id.ToString(), users[2].UserId);
    }

    [Fact]
    public async Task GetUsersByIdsAsync_DuplicateIds_AreDeduplicated()
    {
        var a = SeedAccount();

        var users = await _service.GetUsersByIdsAsync(new List<string> { a.Id.ToString(), a.Id.ToString().ToUpperInvariant() });

        Assert.Single(users);
    }

    [Fact]
    public async Task GetUsersByIdsAsync_WithCanceledToken_ThrowsOperationCanceledException()
    {
        var account = SeedAccount();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _service.GetUsersByIdsAsync(
                new List<string> { account.Id.ToString() },
                cancellation.Token));
    }
}
