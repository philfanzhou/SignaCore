using System.Diagnostics.Metrics;
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
            .Setup(service => service.FindCredentialByLoginAsync("corp", "alice"))
            .ReturnsAsync((LdapCredentialEntity?)null);

        var result = await fixture.Validator.ValidateAsync(fixture.Request("alice"));

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
        fixture.AccountService.Setup(service => service.GetCredentialByObjectGuidAsync("corp", identity.ObjectGuid))
            .ReturnsAsync((LdapCredentialEntity?)null);
        fixture.AccountService.Setup(service => service.ProvisionAsync(
                identity,
                fixture.App,
                LdapAccessApprovalSource.AutoProvision,
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new LdapProvisioningResult(account, credential, access, true, true));

        var result = await fixture.Validator.ValidateAsync(fixture.Request("alice"));

        Assert.True(result.IsSuccess);
        Assert.Equal(account.Id, result.Account!.Id);
        Assert.Equal(credential.Id, result.LdapCredentialId);
        Assert.Equal(IdentityConstants.AuthMethodLdap, result.AuthMethod);
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
        fixture.AccountService.Setup(service => service.GetCredentialByObjectGuidAsync("corp", identity.ObjectGuid))
            .ReturnsAsync((LdapCredentialEntity?)null);

        var result = await fixture.Validator.ValidateAsync(fixture.Request("alice"));

        Assert.False(result.IsSuccess);
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

        var result = await fixture.Validator.ValidateAsync(fixture.Request("alice"));

        Assert.False(result.IsSuccess);
        fixture.DirectoryClient.Verify(client => client.ResolveDirectory(It.IsAny<string>()), Times.Never);
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
            LoginAttemptRepository.Setup(repository => repository.GetByUsernameAsync(It.IsAny<string>()))
                .ReturnsAsync((LoginAttemptEntity?)null);
            LoginAttemptRepository.Setup(repository => repository.RecordFailureAsync(
                    It.IsAny<string>(), It.IsAny<DateTimeOffset>()))
                .ReturnsAsync(new LoginAttemptEntity());

            var unitOfWork = new Mock<IUnitOfWork>();
            unitOfWork.Setup(item => item.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
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
                unitOfWork.Object,
                CreateMetrics(),
                NullLogger<LdapValidator>.Instance);
        }

        public ValidationRequest Request(string username) => new()
        {
            GrantType = IdentityConstants.GrantTypeLdap,
            Username = username,
            Password = "Password1",
            AppId = App.AppId,
            App = App
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
