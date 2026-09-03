using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Validators;
using SignaCore.Domain.Services.Ldap;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Services.WeChat;
using Xunit;

namespace SignaCore.Tests;

public class RefreshTokenValidatorTests
{
    private static IdentityDbContext CreateInMemoryContext()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        return new IdentityDbContext(options);
    }

    private static ILogger<RefreshTokenValidator> CreateLogger() => NullLogger<RefreshTokenValidator>.Instance;

    private static RefreshTokenValidator CreateValidator(
        IRefreshTokenRepository refreshTokenRepository,
        IAccountRepository accountRepository,
        IWechatAdmissionService? wechatAdmissionService = null,
        IAppExchangeTrustRepository? exchangeTrustRepository = null,
        ISmsAdmissionService? smsAdmissionService = null) =>
        new(
            refreshTokenRepository,
            accountRepository,
            // Default: no application trusts any other, which is the shape of a deployment that
            // never configures an exchange.
            exchangeTrustRepository ?? new Mock<IAppExchangeTrustRepository>().Object,
            new Mock<ILdapAccountService>().Object,
            new Mock<ILdapDirectoryClient>().Object,
            smsAdmissionService ?? new Mock<ISmsAdmissionService>().Object,
            wechatAdmissionService ?? new Mock<IWechatAdmissionService>().Object,
            CreateLogger());

    private static IAppExchangeTrustRepository TrustFrom(Guid appRegistrationId, string sourceAppId)
    {
        var repository = new Mock<IAppExchangeTrustRepository>();
        repository
            .Setup(item => item.IsTrustedSourceAsync(appRegistrationId, sourceAppId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        return repository.Object;
    }

    [Fact]
    public async Task ValidateAsync_WithValidRefreshToken_ReturnsSuccess()
    {
        var context = CreateInMemoryContext();
        var accountId = Guid.NewGuid();
        var account = new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        context.Accounts.Add(account);

        var refreshToken = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = "valid_refresh_token",
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            IsRevoked = false,
            CreatedAt = DateTimeOffset.UtcNow,
            AppId = "app-1"
        };
        context.RefreshTokens.Add(refreshToken);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("valid_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "valid_refresh_token",
            AppId = "app-1"
        });

        Assert.True(result.IsSuccess);
        Assert.Equal(IdentityConstants.AuthMethodRefreshToken, result.AuthMethod);
        Assert.Equal(accountId, result.Account!.Id);
    }

    [Fact]
    public async Task ValidateAsync_WithExpiredRefreshToken_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        var accountId = Guid.NewGuid();
        var account = new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        context.Accounts.Add(account);

        var refreshToken = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = "expired_refresh_token",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(-1),
            IsRevoked = false,
            CreatedAt = DateTimeOffset.UtcNow,
            AppId = "app-1"
        };
        context.RefreshTokens.Add(refreshToken);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("expired_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "expired_refresh_token"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Refresh token has expired", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithRevokedRefreshToken_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        var accountId = Guid.NewGuid();
        var account = new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        context.Accounts.Add(account);

        var refreshToken = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = "revoked_refresh_token",
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            IsRevoked = true,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        context.RefreshTokens.Add(refreshToken);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("revoked_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "revoked_refresh_token"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Refresh token has been revoked", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithEmptyRefreshToken_ReturnsFailure()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        var accountRepoMock = new Mock<IAccountRepository>();

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = ""
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Refresh token cannot be empty", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithNonexistentRefreshToken_ReturnsFailure()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync(It.IsAny<string>())).ReturnsAsync((RefreshTokenEntity?)null);
        var accountRepoMock = new Mock<IAccountRepository>();

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "nonexistent_token"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Invalid refresh token", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithInactiveAccount_ReturnsFailure()
    {
        var accountId = Guid.NewGuid();
        var account = new AccountEntity
        {
            Id = accountId,
            IsActive = false,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var refreshToken = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = "valid_refresh_token",
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            IsRevoked = false,
            CreatedAt = DateTimeOffset.UtcNow,
            AppId = "app-1"
        };

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("valid_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "valid_refresh_token",
            AppId = "app-1"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Account is disabled", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithCrossAppExchange_ReturnsFailure()
    {
        // A refresh token is an application-bound credential. Without an administered exchange
        // trust, a second application must start its own login flow instead of presenting it.
        var (account, token, tokenRepository, accountRepository) =
            CreateCrossApplicationFixture("cross_app_refresh_token", "source_app_id");
        var targetApp = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "target_app_id" };

        var validator = CreateValidator(tokenRepository.Object, accountRepository.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = token.TokenValue,
            AppId = targetApp.AppId,
            App = targetApp
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Refresh token is not valid for this application", result.ErrorMessage);
        Assert.False(result.IsCrossApplicationExchange);
        accountRepository.Verify(item => item.GetByIdAsync(It.IsAny<Guid>()), Times.Never);
        Assert.NotNull(account);
    }

    [Fact]
    public async Task ValidateAsync_CrossApplicationRefresh_IsAdmittedByAnExchangeTrust()
    {
        var (account, token, tokenRepository, accountRepository) =
            CreateCrossApplicationFixture("trusted_refresh_token", "source_app_id");
        var targetApp = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "target_app_id" };

        var validator = CreateValidator(
            tokenRepository.Object,
            accountRepository.Object,
            exchangeTrustRepository: TrustFrom(targetApp.Id, token.AppId));

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = token.TokenValue,
            AppId = targetApp.AppId,
            App = targetApp
        });

        Assert.True(result.IsSuccess);
        Assert.Equal(account.Id, result.Account.Id);
        // The issuance path reads these two to mint instead of rotate.
        Assert.True(result.IsCrossApplicationExchange);
        Assert.Equal("source_app_id", result.SourceAppId);
    }

    [Fact]
    public async Task ValidateAsync_CrossApplicationRefresh_DoesNotComposeAcrossTwoTrusts()
    {
        // A → B and B → C must not add up to A → C. A token minted by an exchange carries the
        // application it came from, and that is what disqualifies it from a second exchange.
        var (_, token, tokenRepository, accountRepository) =
            CreateCrossApplicationFixture("second_hop_refresh_token", "middle_app_id");
        token.SourceAppId = "first_app_id";
        var targetApp = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "third_app_id" };

        var validator = CreateValidator(
            tokenRepository.Object,
            accountRepository.Object,
            exchangeTrustRepository: TrustFrom(targetApp.Id, token.AppId));

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = token.TokenValue,
            AppId = targetApp.AppId,
            App = targetApp
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Refresh token is not valid for this application", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_CrossApplicationRefresh_DerivesSmsAdmissionAsExchangeGranted()
    {
        var (account, token, tokenRepository, accountRepository) =
            CreateCrossApplicationFixture("sms_exchange_refresh_token", "source_app_id");
        var loginId = Guid.NewGuid();
        token.SmsUserLoginId = loginId;
        var targetApp = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "target_app_id",
            SmsLoginMode = SmsLoginMode.AutoProvision
        };

        var login = new UserLoginEntity { Id = loginId, AccountId = account.Id, ProviderUserId = "+8613800138000" };
        var smsAdmission = new Mock<ISmsAdmissionService>();
        smsAdmission
            .Setup(item => item.FindByLoginIdAsync(targetApp.Id, loginId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((SmsAdmission?)null);
        smsAdmission
            .Setup(item => item.GrantByLoginIdAsync(
                targetApp, loginId, SmsAccessApprovalSource.ExchangeGranted, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SmsAdmission(
                account,
                login,
                new AppSmsAccessEntity
                {
                    AppRegistrationId = targetApp.Id,
                    UserLoginId = loginId,
                    ApprovalSource = SmsAccessApprovalSource.ExchangeGranted,
                    IsActive = true
                }));

        var validator = CreateValidator(
            tokenRepository.Object,
            accountRepository.Object,
            exchangeTrustRepository: TrustFrom(targetApp.Id, token.AppId),
            smsAdmissionService: smsAdmission.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = token.TokenValue,
            AppId = targetApp.AppId,
            App = targetApp
        });

        Assert.True(result.IsSuccess);
        Assert.True(result.IsCrossApplicationExchange);
        // Recorded as derived, not as a verified SMS login: no OTP was checked for this application.
        smsAdmission.Verify(item => item.GrantByLoginIdAsync(
            targetApp, loginId, SmsAccessApprovalSource.ExchangeGranted, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ValidateAsync_CrossApplicationRefresh_DoesNotDeriveAdmissionUnderManualApproval()
    {
        var (account, token, tokenRepository, accountRepository) =
            CreateCrossApplicationFixture("manual_exchange_refresh_token", "source_app_id");
        var loginId = Guid.NewGuid();
        token.SmsUserLoginId = loginId;
        var targetApp = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "target_app_id",
            SmsLoginMode = SmsLoginMode.ManualApproval
        };

        var smsAdmission = new Mock<ISmsAdmissionService>();
        smsAdmission
            .Setup(item => item.FindByLoginIdAsync(targetApp.Id, loginId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((SmsAdmission?)null);

        var validator = CreateValidator(
            tokenRepository.Object,
            accountRepository.Object,
            exchangeTrustRepository: TrustFrom(targetApp.Id, token.AppId),
            smsAdmissionService: smsAdmission.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = token.TokenValue,
            AppId = targetApp.AppId,
            App = targetApp
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("SMS access has been revoked", result.ErrorMessage);
        smsAdmission.Verify(item => item.GrantByLoginIdAsync(
            It.IsAny<AppRegistrationEntity>(), It.IsAny<Guid>(), It.IsAny<SmsAccessApprovalSource>(),
            It.IsAny<CancellationToken>()), Times.Never);
        Assert.NotNull(account);
    }

    private static (AccountEntity Account, RefreshTokenEntity Token,
        Mock<IRefreshTokenRepository> TokenRepository, Mock<IAccountRepository> AccountRepository)
        CreateCrossApplicationFixture(string tokenValue, string sourceAppId)
    {
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        var token = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            TokenValue = tokenValue,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            IsRevoked = false,
            CreatedAt = DateTimeOffset.UtcNow,
            AppId = sourceAppId
        };
        var tokenRepository = new Mock<IRefreshTokenRepository>();
        tokenRepository.Setup(item => item.GetByTokenValueAsync(tokenValue)).ReturnsAsync(token);
        var accountRepository = new Mock<IAccountRepository>();
        accountRepository.Setup(item => item.GetByIdAsync(account.Id)).ReturnsAsync(account);
        return (account, token, tokenRepository, accountRepository);
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task ValidateAsync_WechatBoundToken_FollowsCurrentApplicationAdmission(
        bool accessIsActive,
        bool expectedSuccess)
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "app-1",
            WechatLoginMode = WechatLoginMode.BindRequired
        };
        var login = new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            ProviderName = IdentityConstants.AuthMethodWechat,
            ProviderUserId = "open-id"
        };
        var token = new RefreshTokenEntity
        {
            AccountId = account.Id,
            TokenValue = "wechat-refresh",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = app.AppId,
            WechatUserLoginId = login.Id
        };
        var tokenRepository = new Mock<IRefreshTokenRepository>();
        tokenRepository.Setup(repository => repository.GetByTokenValueAsync(token.TokenValue)).ReturnsAsync(token);
        var accountRepository = new Mock<IAccountRepository>();
        accountRepository.Setup(repository => repository.GetByIdAsync(account.Id)).ReturnsAsync(account);
        var wechatAdmission = new Mock<IWechatAdmissionService>();
        wechatAdmission.Setup(service => service.FindByLoginIdAsync(app.Id, login.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new WechatAdmission(
                account,
                login,
                new AppWechatAccessEntity { AppRegistrationId = app.Id, UserLoginId = login.Id, IsActive = accessIsActive }));

        var validator = CreateValidator(tokenRepository.Object, accountRepository.Object, wechatAdmission.Object);
        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = token.TokenValue,
            AppId = app.AppId,
            App = app
        });

        Assert.Equal(expectedSuccess, result.IsSuccess);
        if (expectedSuccess)
        {
            Assert.Equal(login.Id, result.WechatUserLoginId);
        }
        else
        {
            Assert.Equal("WeChat access has been revoked", result.ErrorMessage);
        }
    }

    [Fact]
    public async Task ValidateAsync_WechatBoundToken_IsRejectedWhenApplicationDisablesWechat()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "app-1",
            WechatLoginMode = WechatLoginMode.Disabled
        };
        var token = new RefreshTokenEntity
        {
            AccountId = account.Id,
            TokenValue = "wechat-refresh",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = app.AppId,
            WechatUserLoginId = Guid.NewGuid()
        };
        var tokenRepository = new Mock<IRefreshTokenRepository>();
        tokenRepository.Setup(repository => repository.GetByTokenValueAsync(token.TokenValue)).ReturnsAsync(token);
        var accountRepository = new Mock<IAccountRepository>();
        accountRepository.Setup(repository => repository.GetByIdAsync(account.Id)).ReturnsAsync(account);
        var wechatAdmission = new Mock<IWechatAdmissionService>();

        var validator = CreateValidator(tokenRepository.Object, accountRepository.Object, wechatAdmission.Object);
        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = token.TokenValue,
            AppId = app.AppId,
            App = app
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("WeChat login is disabled for this application", result.ErrorMessage);
        wechatAdmission.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    public async Task ValidateAsync_LdapRefresh_PropagatesTokenOnSuccessAndRejection(
        bool crossApplication, bool admitted)
    {
        using var cancellation = new CancellationTokenSource();
        var calls = new List<string>();
        var (validator, request) = CreateLdapCancellationFixture(cancellation, calls, crossApplication, admitted);

        var result = await validator.ValidateAsync(request);

        Assert.Equal(admitted, result.IsSuccess);
        Assert.Equal(admitted && crossApplication, result.IsCrossApplicationExchange);
        var expected = new List<string> { "token" };
        if (crossApplication) expected.Add("trust");
        expected.AddRange(["account", "credential", "access"]);
        if (admitted)
        {
            if (crossApplication) expected.Add("grant");
            expected.Add("directory");
        }
        else
        {
            Assert.Equal("LDAP access has been revoked", result.ErrorMessage);
        }
        Assert.Equal(expected, calls);
    }

    [Theory]
    [InlineData("token")]
    [InlineData("trust")]
    [InlineData("account")]
    [InlineData("credential")]
    [InlineData("access")]
    public async Task ValidateAsync_CancelledLdapRefreshRead_DoesNotReadFurtherOrGrantAdmission(string cancelAt)
    {
        using var cancellation = new CancellationTokenSource();
        var calls = new List<string>();
        var (validator, request) = CreateLdapCancellationFixture(cancellation, calls, true, true, cancelAt);

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => validator.ValidateAsync(request));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        string[] expected = ["token", "trust", "account", "credential", "access"];
        Assert.Equal(expected.Take(Array.IndexOf(expected, cancelAt) + 1), calls);
    }

    private static (RefreshTokenValidator Validator, ValidationRequest Request) CreateLdapCancellationFixture(
        CancellationTokenSource cancellation,
        List<string> calls,
        bool crossApplication,
        bool admitted,
        string? cancelAt = null)
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(), AppId = "target-app", LdapLoginMode = LdapLoginMode.AutoProvision
        };
        var credential = new LdapCredentialEntity
        {
            Id = Guid.NewGuid(), AccountId = account.Id, DirectoryKey = "corp",
            ObjectGuid = Guid.NewGuid(), UserPrincipalName = "alice@corp.example.test"
        };
        var token = new RefreshTokenEntity
        {
            AccountId = account.Id, TokenValue = "test-refresh", ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = crossApplication ? "source-app" : app.AppId, LdapCredentialId = credential.Id
        };
        var access = new AppLdapAccessEntity
        {
            AppRegistrationId = app.Id, LdapCredentialId = credential.Id,
            IsActive = admitted, ApprovalSource = LdapAccessApprovalSource.ExchangeGranted
        };
        void Observe(string stage, CancellationToken received)
        {
            Assert.Equal(cancellation.Token, received);
            calls.Add(stage);
            if (stage == cancelAt) cancellation.Cancel();
            received.ThrowIfCancellationRequested();
        }

        var tokens = new Mock<IRefreshTokenRepository>();
        tokens.Setup(repository => repository.GetByTokenValueAsync(token.TokenValue, It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((_, ct) => Observe("token", ct)).ReturnsAsync(token);
        var accounts = new Mock<IAccountRepository>();
        accounts.Setup(repository => repository.GetByIdAsync(account.Id, It.IsAny<CancellationToken>()))
            .Callback<Guid, CancellationToken>((_, ct) => Observe("account", ct)).ReturnsAsync(account);
        var trusts = new Mock<IAppExchangeTrustRepository>();
        trusts.Setup(repository => repository.IsTrustedSourceAsync(app.Id, token.AppId, It.IsAny<CancellationToken>()))
            .Callback<Guid, string, CancellationToken>((_, _, ct) => Observe("trust", ct)).ReturnsAsync(true);
        var ldapAccounts = new Mock<ILdapAccountService>();
        ldapAccounts.Setup(service => service.GetCredentialAsync(credential.Id, It.IsAny<CancellationToken>()))
            .Callback<Guid, CancellationToken>((_, ct) => Observe("credential", ct)).ReturnsAsync(credential);
        ldapAccounts.Setup(service => service.GetAccessAsync(app.Id, credential.Id, It.IsAny<CancellationToken>()))
            .Callback<Guid, Guid, CancellationToken>((_, _, ct) => Observe("access", ct))
            .ReturnsAsync(crossApplication && admitted ? null : access);
        ldapAccounts.Setup(service => service.GrantAccessAsync(
                app.Id, credential.Id, LdapAccessApprovalSource.ExchangeGranted, It.IsAny<CancellationToken>()))
            .Callback<Guid, Guid, LdapAccessApprovalSource, CancellationToken>((_, _, _, ct) => Observe("grant", ct))
            .ReturnsAsync(access);
        var directory = new Mock<ILdapDirectoryClient>();
        directory.Setup(client => client.IsUserEnabledAsync("corp", credential.ObjectGuid, It.IsAny<CancellationToken>()))
            .Callback<string, Guid, CancellationToken>((_, _, ct) => Observe("directory", ct)).ReturnsAsync(true);
        return (new RefreshTokenValidator(tokens.Object, accounts.Object, trusts.Object, ldapAccounts.Object,
            directory.Object, new Mock<ISmsAdmissionService>().Object, new Mock<IWechatAdmissionService>().Object,
            CreateLogger()), new ValidationRequest
            {
                GrantType = IdentityConstants.GrantTypeRefreshToken, RefreshToken = token.TokenValue,
                AppId = app.AppId, App = app, CancellationToken = cancellation.Token
            });
    }

    [Fact]
    public void GrantType_ReturnsRefreshToken()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        var accountRepoMock = new Mock<IAccountRepository>();

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

        Assert.Equal(IdentityConstants.GrantTypeRefreshToken, validator.GrantType);
    }

    [Fact]
    public async Task ValidateAsync_AutoProvisionGrant_DoesNotSurviveSwitchToManualMode()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "app-1",
            LdapLoginMode = LdapLoginMode.ManualApproval
        };
        var credential = new LdapCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            DirectoryKey = "corp",
            ObjectGuid = Guid.NewGuid(),
            UserPrincipalName = "alice@corp.example.com"
        };
        var token = new RefreshTokenEntity
        {
            AccountId = account.Id,
            TokenValue = "ldap-refresh",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = app.AppId,
            LdapCredentialId = credential.Id
        };
        var tokenRepository = new Mock<IRefreshTokenRepository>();
        tokenRepository.Setup(repository => repository.GetByTokenValueAsync(token.TokenValue)).ReturnsAsync(token);
        var accountRepository = new Mock<IAccountRepository>();
        accountRepository.Setup(repository => repository.GetByIdAsync(account.Id)).ReturnsAsync(account);
        var ldapAccounts = new Mock<ILdapAccountService>();
        ldapAccounts.Setup(service => service.GetCredentialAsync(credential.Id)).ReturnsAsync(credential);
        ldapAccounts.Setup(service => service.GetAccessAsync(app.Id, credential.Id)).ReturnsAsync(
            new AppLdapAccessEntity
            {
                AppRegistrationId = app.Id,
                LdapCredentialId = credential.Id,
                ApprovalSource = LdapAccessApprovalSource.AutoProvision,
                IsActive = true
            });
        var directoryClient = new Mock<ILdapDirectoryClient>();
        var validator = new RefreshTokenValidator(
            tokenRepository.Object,
            accountRepository.Object,
            new Mock<IAppExchangeTrustRepository>().Object,
            ldapAccounts.Object,
            directoryClient.Object,
            new Mock<ISmsAdmissionService>().Object,
            new Mock<IWechatAdmissionService>().Object,
            CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = token.TokenValue,
            AppId = app.AppId,
            App = app
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("LDAP access has been revoked", result.ErrorMessage);
        directoryClient.Verify(client => client.IsUserEnabledAsync(
            It.IsAny<string>(), It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
