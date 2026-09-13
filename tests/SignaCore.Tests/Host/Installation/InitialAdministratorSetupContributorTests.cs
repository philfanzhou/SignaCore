using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Installation;
using Xunit;

namespace SignaCore.Tests.Host.Installation;

/// <summary>
/// The initial administrator contributor contract: read-only validation, staging-only
/// registration with fresh identifiers per instance, and no credential leaking through string
/// projections.
/// </summary>
public sealed class InitialAdministratorSetupContributorTests
{
    private const string Username = "setup_admin";
    private const string Password = "SetupAdmin123";
    private static readonly IPasswordHasher FastHasher =
        new BCryptPasswordHasher(new PasswordHasherOptions { WorkFactor = 4 });

    [Fact]
    public async Task ValidateAsync_OnACleanDatabase_SucceedsWithoutStagingAnything()
    {
        await using var database = await TestDatabase.CreateAsync();
        var contributor = CreateContributor(database.Context);

        var result = await contributor.ValidateAsync(TestContext.Current.CancellationToken);

        Assert.True(result.Succeeded);
        Assert.False(database.Context.ChangeTracker.HasChanges());
        Assert.Empty(database.Context.Accounts.Local);
        Assert.Empty(database.Context.PasswordCredentials.Local);
    }

    [Fact]
    public async Task ValidateAsync_RejectsANormalizedDuplicateUsername()
    {
        await using var database = await TestDatabase.CreateAsync();
        await SeedCredentialAsync(database.Context, "SETUP_ADMIN");
        var contributor = CreateContributor(database.Context, username: "setup_admin");

        var result = await contributor.ValidateAsync(TestContext.Current.CancellationToken);

        Assert.False(result.Succeeded);
        Assert.Equal(
            InitialAdministratorSetupContributor.UsernameTakenErrorCode,
            result.ErrorCode);
        Assert.False(database.Context.ChangeTracker.HasChanges());
    }

    [Fact]
    public async Task ValidateAsync_RejectsAPasswordThatViolatesThePolicy()
    {
        await using var database = await TestDatabase.CreateAsync();
        var contributor = CreateContributor(database.Context, password: "short");

        var result = await contributor.ValidateAsync(TestContext.Current.CancellationToken);

        Assert.False(result.Succeeded);
        Assert.Equal(
            InitialAdministratorSetupContributor.InvalidPasswordErrorCode,
            result.ErrorCode);
    }

    [Fact]
    public async Task RegisterAsync_StagesOneAccountAndOneVerifiableCredential()
    {
        await using var database = await TestDatabase.CreateAsync();
        var contributor = CreateContributor(database.Context);

        var result = await contributor.RegisterAsync(TestContext.Current.CancellationToken);

        Assert.True(result.Succeeded);
        var account = Assert.Single(database.Context.Accounts.Local);
        var credential = Assert.Single(database.Context.PasswordCredentials.Local);
        Assert.True(account.IsActive);
        Assert.Equal(contributor.AccountId, account.Id);
        Assert.Equal(account.Id, credential.AccountId);
        Assert.Equal(Username, credential.Username);
        Assert.NotEqual(Username, credential.PasswordHash);
        Assert.True(FastHasher.VerifyPassword(Password, credential.PasswordHash));
        // Normalization stays owned by the context's SaveChanges pipeline.
        Assert.Equal(string.Empty, credential.UsernameNormalized);
    }

    [Fact]
    public async Task RegisterAsync_GeneratesFreshIdentifiersPerContributorInstance()
    {
        await using var database = await TestDatabase.CreateAsync();
        var first = CreateContributor(database.Context);
        var second = CreateContributor(database.Context);

        await first.RegisterAsync(TestContext.Current.CancellationToken);
        await second.RegisterAsync(TestContext.Current.CancellationToken);

        Assert.NotEqual(first.AccountId, second.AccountId);
        var credentialUsernames = database.Context.PasswordCredentials.Local
            .Select(credential => credential.Username)
            .ToList();
        Assert.Equal(2, credentialUsernames.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PreCanceledToken_DoesNoWork(bool duringValidation)
    {
        await using var database = await TestDatabase.CreateAsync();
        var contributor = CreateContributor(database.Context);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        if (duringValidation)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                async () => await contributor.ValidateAsync(cancellation.Token));
        }
        else
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                async () => await contributor.RegisterAsync(cancellation.Token));
        }

        Assert.Equal(Guid.Empty, contributor.AccountId);
        Assert.Empty(database.Context.Accounts.Local);
        Assert.Empty(database.Context.PasswordCredentials.Local);
    }

    [Fact]
    public void InputToString_NeverContainsTheCredentials()
    {
        var input = new InitialAdministratorSetupInput(Username, Password);

        Assert.Equal(nameof(InitialAdministratorSetupInput), input.ToString());
        Assert.DoesNotContain(Password, input.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Username, input.ToString(), StringComparison.Ordinal);
    }

    internal static InitialAdministratorSetupContributor CreateContributor(
        IdentityDbContext context,
        string username = Username,
        string password = Password) =>
        new(
            context,
            FastHasher,
            new DefaultPasswordPolicy(),
            new InitialAdministratorSetupInput(username, password));

    internal static async Task SeedCredentialAsync(IdentityDbContext context, string username)
    {
        var accountId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = username,
            UsernameNormalized = IdentityValueNormalizer.Normalize(username),
            PasswordHash = "existing-test-hash",
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
    }

    internal sealed class TestDatabase : IAsyncDisposable
    {
        private TestDatabase(SqliteConnection connection, IdentityDbContext context)
        {
            Connection = connection;
            Context = context;
        }

        private SqliteConnection Connection { get; }

        public IdentityDbContext Context { get; }

        public static async Task<TestDatabase> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var context = new IdentityDbContext(
                new DbContextOptionsBuilder<IdentityDbContext>()
                    .UseSqlite(connection)
                    .Options);
            await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return new TestDatabase(connection, context);
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }
}
