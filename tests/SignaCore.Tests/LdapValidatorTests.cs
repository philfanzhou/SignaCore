using System.Diagnostics.Metrics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services.Ldap;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests;

public sealed class LdapValidatorTests
{
    private static readonly LdapDirectoryOptions Directory = new()
    {
        Key = "corp",
        Hosts = ["dc01.corp.example.com"],
        BaseDn = "DC=corp,DC=example,DC=com",
        BindUsername = "svc@corp.example.com",
        BindPassword = "secret",
        UpnSuffixes = ["corp.example.com"],
        NetbiosNames = ["CORP"]
    };

    [Fact]
    public async Task ManualApproval_UnregisteredUser_DoesNotContactDirectory()
    {
        var fixture = new Fixture(LdapLoginMode.ManualApproval);
        fixture.AccountService
            .Setup(service => service.FindCredentialByLoginAsync("corp", "alice", It.IsAny<CancellationToken>()))
            .ReturnsAsync((LdapCredentialEntity?)null);

        var result = await fixture.Validator.ValidateAsync(fixture.Request("alice", TestContext.Current.CancellationToken));

        Assert.False(result.IsSuccess);
        Assert.Equal("Wrong username or password", result.ErrorMessage);
        fixture.DirectoryClient.Verify(client => client.FindUserAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        fixture.DirectoryClient.Verify(client => client.ValidateCredentialsAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task AutoProvision_ValidDirectoryUser_CreatesApplicationAccess()
    {
        var fixture = new Fixture(LdapLoginMode.AutoProvision);
        var identity = new LdapDirectoryIdentity(
            "corp", Guid.NewGuid(), "alice@corp.example.com", "alice", true);
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var credential = new LdapCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            DirectoryKey = "corp",
            ObjectGuid = identity.ObjectGuid,
            UserPrincipalName = identity.UserPrincipalName,
            SamAccountName = identity.SamAccountName
        };
        var access = new AppLdapAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = fixture.App.Id,
            LdapCredentialId = credential.Id,
            ApprovalSource = LdapAccessApprovalSource.AutoProvision,
            IsActive = true
        };
        fixture.DirectoryClient.Setup(client => client.FindUserAsync(
                "corp", "alice", It.IsAny<CancellationToken>()))
            .ReturnsAsync(identity);
        fixture.DirectoryClient.Setup(client => client.ValidateCredentialsAsync(
                "corp", identity.UserPrincipalName, "Password1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(LdapCredentialValidationResult.Success);
        fixture.AccountService.Setup(service => service.GetCredentialByObjectGuidAsync("corp", identity.ObjectGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync((LdapCredentialEntity?)null);
        fixture.AccountService.Setup(service => service.ProvisionAsync(
                identity,
                fixture.App,
                LdapAccessApprovalSource.AutoProvision,
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new LdapProvisioningResult(account, credential, access, true, true));
        fixture.LoginAttemptRepository.Setup(repository => repository.GetByUsernameAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new LoginAttemptEntity
            {
                Id = Guid.NewGuid(),
                Username = "ldap:corp:prior",
                FailedAttempts = 1,
                LastAttemptAt = DateTimeOffset.UtcNow
            });

        var result = await fixture.Validator.ValidateAsync(fixture.Request("alice", TestContext.Current.CancellationToken));

        Assert.True(result.IsSuccess);
        Assert.Equal(account.Id, result.Account!.Id);
        Assert.Equal(credential.Id, result.LdapCredentialId);
        Assert.Equal(IdentityConstants.AuthMethodLdap, result.AuthMethod);
        Assert.Equal(LoginAttemptChangeKind.Clear, result.LoginAttemptChange?.Kind);
        fixture.LoginAttemptRepository.Verify(repository => repository.RemoveAsync(
            It.IsAny<LoginAttemptEntity>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task AutoProvision_InvalidPassword_DoesNotCreateLocalAccount()
    {
        var fixture = new Fixture(LdapLoginMode.AutoProvision);
        var identity = new LdapDirectoryIdentity(
            "corp", Guid.NewGuid(), "alice@corp.example.com", "alice", true);
        fixture.DirectoryClient.Setup(client => client.FindUserAsync(
                "corp", "alice", It.IsAny<CancellationToken>()))
            .ReturnsAsync(identity);
        fixture.DirectoryClient.Setup(client => client.ValidateCredentialsAsync(
                "corp", identity.UserPrincipalName, "Password1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(LdapCredentialValidationResult.InvalidCredentials);
        fixture.AccountService.Setup(service => service.GetCredentialByObjectGuidAsync("corp", identity.ObjectGuid, It.IsAny<CancellationToken>()))
            .ReturnsAsync((LdapCredentialEntity?)null);

        var result = await fixture.Validator.ValidateAsync(fixture.Request("alice", TestContext.Current.CancellationToken));

        Assert.False(result.IsSuccess);
        Assert.Equal(LoginAttemptChangeKind.RecordFailure, result.LoginAttemptChange?.Kind);
        fixture.LoginAttemptRepository.Verify(repository => repository.RecordFailureAsync(
            It.IsAny<string>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<CancellationToken>()), Times.Never);
        fixture.AccountService.Verify(service => service.ProvisionAsync(
            It.IsAny<LdapDirectoryIdentity>(),
            It.IsAny<AppRegistrationEntity>(),
            It.IsAny<LdapAccessApprovalSource>(),
            It.IsAny<Guid?>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DisabledPolicy_DoesNotResolveDirectory()
    {
        var fixture = new Fixture(LdapLoginMode.Disabled);

        var result = await fixture.Validator.ValidateAsync(fixture.Request("alice", TestContext.Current.CancellationToken));

        Assert.False(result.IsSuccess);
        fixture.DirectoryClient.Verify(client => client.ResolveDirectory(It.IsAny<string>()), Times.Never);
    }

    [Theory]
    [InlineData(LdapLoginMode.ManualApproval, true)]
    [InlineData(LdapLoginMode.ManualApproval, false)]
    [InlineData(LdapLoginMode.AutoProvision, true)]
    [InlineData(LdapLoginMode.AutoProvision, false)]
    public async Task ValidateAsync_PropagatesTokenThroughReadsAndBind(
        LdapLoginMode mode, bool bindSucceeds)
    {
        using var cancellation = new CancellationTokenSource();
        var calls = new List<string>();
        var fixture = CreateCancellationFixture(mode, cancellation, calls, bindSucceeds: bindSucceeds);

        var result = await fixture.Validator.ValidateAsync(fixture.Request("alice", cancellation.Token));

        Assert.Equal(bindSucceeds, result.IsSuccess);
        var expected = ExpectedReadCalls(mode).Append("bind");
        if (mode == LdapLoginMode.AutoProvision && bindSucceeds)
            expected = expected.Append("provision");
        Assert.Equal(expected, calls);
    }

    [Theory]
    [InlineData(LdapLoginMode.ManualApproval, "credential")]
    [InlineData(LdapLoginMode.ManualApproval, "access")]
    [InlineData(LdapLoginMode.ManualApproval, "account")]
    [InlineData(LdapLoginMode.ManualApproval, "attempt")]
    [InlineData(LdapLoginMode.AutoProvision, "credential")]
    [InlineData(LdapLoginMode.AutoProvision, "account")]
    [InlineData(LdapLoginMode.AutoProvision, "access")]
    [InlineData(LdapLoginMode.AutoProvision, "attempt")]
    public async Task ValidateAsync_CancelledRead_StopsBeforeLaterReadsBindAndProvision(
        LdapLoginMode mode, string cancelAt)
    {
        using var cancellation = new CancellationTokenSource();
        var calls = new List<string>();
        var fixture = CreateCancellationFixture(mode, cancellation, calls, cancelAt);

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            fixture.Validator.ValidateAsync(fixture.Request("alice", cancellation.Token)));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        var expected = ExpectedReadCalls(mode);
        Assert.Equal(expected.Take(Array.IndexOf(expected, cancelAt) + 1), calls);
    }

    [Theory]
    [InlineData("login")]
    [InlineData("credential")]
    [InlineData("objectGuid")]
    [InlineData("access")]
    public async Task AccountRead_WithCancelledToken_DoesNotReturnDatabaseResult(string read)
    {
        await using var context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        var service = new LdapAccountService(context);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => read switch
        {
            "login" => service.FindCredentialByLoginAsync("corp", "alice", cancellation.Token),
            "credential" => service.GetCredentialAsync(Guid.NewGuid(), cancellation.Token),
            "objectGuid" => service.GetCredentialByObjectGuidAsync("corp", Guid.NewGuid(), cancellation.Token),
            "access" => (Task)service.GetAccessAsync(Guid.NewGuid(), Guid.NewGuid(), cancellation.Token),
            _ => throw new ArgumentOutOfRangeException(nameof(read))
        });

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.False(context.ChangeTracker.HasChanges());
    }

    private static string[] ExpectedReadCalls(LdapLoginMode mode) => mode == LdapLoginMode.ManualApproval
        ? ["credential", "access", "account", "attempt"]
        : ["find", "credential", "account", "access", "attempt"];

    private static Fixture CreateCancellationFixture(
        LdapLoginMode mode,
        CancellationTokenSource cancellation,
        List<string> calls,
        string? cancelAt = null,
        bool bindSucceeds = true)
    {
        var fixture = new Fixture(mode);
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var identity = new LdapDirectoryIdentity("corp", Guid.NewGuid(), "alice@corp.example.test", "alice", true);
        var credential = new LdapCredentialEntity
        {
            Id = Guid.NewGuid(), AccountId = account.Id, DirectoryKey = identity.DirectoryKey,
            ObjectGuid = identity.ObjectGuid, UserPrincipalName = identity.UserPrincipalName
        };
        var access = new AppLdapAccessEntity
        {
            AppRegistrationId = fixture.App.Id, LdapCredentialId = credential.Id,
            IsActive = true, ApprovalSource = LdapAccessApprovalSource.Admin
        };

        void Observe(string stage, CancellationToken received)
        {
            Assert.Equal(cancellation.Token, received);
            calls.Add(stage);
            if (stage == cancelAt) cancellation.Cancel();
            received.ThrowIfCancellationRequested();
        }

        fixture.AccountService.Setup(service => service.FindCredentialByLoginAsync(
                "corp", "alice", It.IsAny<CancellationToken>()))
            .Callback<string, string, CancellationToken>((_, _, ct) => Observe("credential", ct))
            .ReturnsAsync(credential);
        fixture.AccountService.Setup(service => service.GetCredentialByObjectGuidAsync(
                "corp", identity.ObjectGuid, It.IsAny<CancellationToken>()))
            .Callback<string, Guid, CancellationToken>((_, _, ct) => Observe("credential", ct))
            .ReturnsAsync(credential);
        fixture.AccountService.Setup(service => service.GetAccessAsync(
                fixture.App.Id, credential.Id, It.IsAny<CancellationToken>()))
            .Callback<Guid, Guid, CancellationToken>((_, _, ct) => Observe("access", ct))
            .ReturnsAsync(access);
        fixture.AccountRepository.Setup(repository => repository.GetByIdAsync(account.Id, It.IsAny<CancellationToken>()))
            .Callback<Guid, CancellationToken>((_, ct) => Observe("account", ct))
            .ReturnsAsync(account);
        fixture.LoginAttemptRepository.Setup(repository => repository.GetByUsernameAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((_, ct) => Observe("attempt", ct))
            .ReturnsAsync((LoginAttemptEntity?)null);
        fixture.DirectoryClient.Setup(client => client.FindUserAsync("corp", "alice", It.IsAny<CancellationToken>()))
            .Callback<string, string, CancellationToken>((_, _, ct) => Observe("find", ct))
            .ReturnsAsync(identity);
        fixture.DirectoryClient.Setup(client => client.ValidateCredentialsAsync(
                "corp", identity.UserPrincipalName, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<string, string, string, CancellationToken>((_, _, _, ct) => Observe("bind", ct))
            .ReturnsAsync(bindSucceeds ? LdapCredentialValidationResult.Success : LdapCredentialValidationResult.InvalidCredentials);
        fixture.AccountService.Setup(service => service.ProvisionAsync(
                identity, fixture.App, LdapAccessApprovalSource.AutoProvision, null,
                It.IsAny<CancellationToken>(), It.IsAny<Func<LdapProvisioningResult, Task>?>()))
            .Callback<LdapDirectoryIdentity, AppRegistrationEntity, LdapAccessApprovalSource, Guid?, CancellationToken,
                Func<LdapProvisioningResult, Task>?>((_, _, _, _, ct, _) => Observe("provision", ct))
            .ReturnsAsync(new LdapProvisioningResult(account, credential, access, false, false));
        return fixture;
    }

    private sealed class Fixture
    {
        public Mock<ILdapDirectoryClient> DirectoryClient { get; } = new();
        public Mock<ILdapAccountService> AccountService { get; } = new();
        public Mock<IAccountRepository> AccountRepository { get; } = new();
        public Mock<ILoginAttemptRepository> LoginAttemptRepository { get; } = new();
        public AppRegistrationEntity App { get; }
        public LdapValidator Validator { get; }

        public Fixture(LdapLoginMode mode)
        {
            App = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = "app-1",
                LdapLoginMode = mode
            };
            DirectoryClient.Setup(client => client.ResolveDirectory(It.IsAny<string>())).Returns(Directory);
            LoginAttemptRepository.Setup(repository => repository.GetByUsernameAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((LoginAttemptEntity?)null);
            Validator = new LdapValidator(
                new LdapOptions
                {
                    Enabled = true,
                    DefaultDirectoryKey = "corp",
                    Directories = [Directory]
                },
                DirectoryClient.Object,
                AccountService.Object,
                AccountRepository.Object,
                LoginAttemptRepository.Object,
                CreateMetrics(),
                NullLogger<LdapValidator>.Instance);
        }

        public ValidationRequest Request(string username, CancellationToken cancellationToken = default) => new()
        {
            GrantType = IdentityConstants.GrantTypeLdap,
            Username = username,
            Password = "Password1",
            AppId = App.AppId,
            App = App,
            CancellationToken = cancellationToken
        };

        private static AuthMetrics CreateMetrics()
        {
            var meterFactory = new Mock<IMeterFactory>();
            meterFactory.Setup(factory => factory.Create(It.IsAny<MeterOptions>()))
                .Returns(new Meter("SignaCore.Ldap.Tests"));
            return new AuthMetrics(meterFactory.Object);
        }
    }
}
