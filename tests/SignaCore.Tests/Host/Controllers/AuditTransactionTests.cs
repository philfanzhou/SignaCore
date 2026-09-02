using System.Data.Common;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Ldap;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using SignaCore.Host.Controllers;
using SignaCore.Host.Http;
using SignaCore.Host.Models;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

public sealed class AuditTransactionTests
{
    [Fact]
    public async Task CreateApp_WhenAuditInsertFails_RollsBackApplicationAndReturnsFailure()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await database.Context.Database.ExecuteSqlRawAsync(
            """
            CREATE TRIGGER fail_audit_insert
            BEFORE INSERT ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit insert failed');
            END;
            """,
            TestContext.Current.CancellationToken);

        var controller = CreateAdminController();

        await Assert.ThrowsAsync<DbUpdateException>(() => controller.CreateApp(
            new AdminCreateAppRequest("Atomic app", null, 0),
            new AppRegistrationRepository(database.Context),
            new CallbackUrlValidator(),
            new EfCoreUnitOfWork(database.Context),
            CreateAuditService(database.Context),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        Assert.False(await database.Context.AppRegistrations.AnyAsync(TestContext.Current.CancellationToken));
        Assert.False(await database.Context.AuditLogs.AnyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CreateApp_WhenBusinessInsertFails_RollsBackAuditAndReturnsFailure()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await database.Context.Database.ExecuteSqlRawAsync(
            """
            CREATE TRIGGER fail_application_insert
            BEFORE INSERT ON app_registrations
            BEGIN
                SELECT RAISE(ABORT, 'application insert failed');
            END;
            """,
            TestContext.Current.CancellationToken);

        var controller = CreateAdminController();

        await Assert.ThrowsAsync<DbUpdateException>(() => controller.CreateApp(
            new AdminCreateAppRequest("Atomic app", null, 0),
            new AppRegistrationRepository(database.Context),
            new CallbackUrlValidator(),
            new EfCoreUnitOfWork(database.Context),
            CreateAuditService(database.Context),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        Assert.False(await database.Context.AppRegistrations.AnyAsync(TestContext.Current.CancellationToken));
        Assert.False(await database.Context.AuditLogs.AnyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SmsCodeSuccess_CommitsSentStateAndEveryLoginHistoryFieldTogether()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var app = CreateSmsApp();
        database.Context.AppRegistrations.Add(app);
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        var (controller, sender) = CreateSmsController(database.Context, app);

        var action = await controller.RequestSmsCode(
            new SmsCodeRequest { Phone = "13800138000" },
            TestContext.Current.CancellationToken);

        Assert.True(Assert.IsType<SmsCodeResponse>(Assert.IsType<OkObjectResult>(action.Result).Value).Success);
        database.Context.ChangeTracker.Clear();
        var otp = await database.Context.Otps.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(OtpStatus.Sent, otp.Status);
        Assert.Equal("message-148", otp.ProviderMessageId);
        Assert.NotNull(otp.SentAt);
        var entry = await database.Context.LoginHistories.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Null(entry.AccountId);
        Assert.Equal("+8613800138000", entry.Username);
        Assert.Equal(IdentityConstants.GrantTypeSms, entry.AuthMethod);
        Assert.Equal("sms_code_sent", entry.EventType);
        Assert.Equal("192.0.2.10", entry.ClientIp);
        Assert.Equal("audit-test-agent", entry.UserAgent);
        Assert.Null(entry.FailureReason);
        Assert.Equal("sms-app", entry.AppId);
        Assert.Equal("correlation-148", entry.CorrelationId);
        sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(),
            It.IsAny<SmsVerificationMessage>(),
            TestContext.Current.CancellationToken), Times.Once);
    }

    [Fact]
    public async Task SmsCode_WhenAuditInsertFails_RollsBackSentStateToPendingDelivery()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var app = CreateSmsApp();
        database.Context.AppRegistrations.Add(app);
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        await FailLoginHistoryInsertAsync(database.Context);
        var (controller, sender) = CreateSmsController(database.Context, app);

        var action = await controller.RequestSmsCode(
            new SmsCodeRequest { Phone = "13800138000" },
            TestContext.Current.CancellationToken);

        Assert.False(Assert.IsType<SmsCodeResponse>(
            Assert.IsType<OkObjectResult>(action.Result).Value).Success);
        database.Context.ChangeTracker.Clear();
        var otp = await database.Context.Otps.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(OtpStatus.PendingDelivery, otp.Status);
        Assert.Null(otp.ProviderMessageId);
        Assert.Null(otp.SentAt);
        Assert.False(await database.Context.LoginHistories.AnyAsync(
            TestContext.Current.CancellationToken));
        sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(),
            It.IsAny<SmsVerificationMessage>(),
            TestContext.Current.CancellationToken), Times.Once);
    }

    [Fact]
    public async Task SmsCode_WhenFinalCommitIsCanceled_LeavesPendingDeliveryWithoutAudit()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var app = CreateSmsApp();
        database.Context.AppRegistrations.Add(app);
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        using var cancellation = new CancellationTokenSource();
        var (controller, sender) = CreateSmsController(
            database.Context,
            app,
            cancellation.Cancel);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => controller.RequestSmsCode(
            new SmsCodeRequest { Phone = "13800138000" },
            cancellation.Token));

        database.Context.ChangeTracker.Clear();
        var otp = await database.Context.Otps.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(OtpStatus.PendingDelivery, otp.Status);
        Assert.Null(otp.ProviderMessageId);
        Assert.Null(otp.SentAt);
        Assert.False(await database.Context.LoginHistories.AnyAsync(
            TestContext.Current.CancellationToken));
        sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(),
            It.IsAny<SmsVerificationMessage>(),
            cancellation.Token), Times.Once);
    }

    [Fact]
    public async Task SmsSuccess_WhenLoginHistoryInsertFails_RollsBackConsumptionAndLoginState()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var target = await SeedSmsLoginAsync(database.Context);
        await FailLoginHistoryInsertAsync(database.Context);
        var service = CreateSmsTokenIssuanceService(
            database.Context,
            CreateSmsValidator(database.Context));

        await Assert.ThrowsAsync<DbUpdateException>(() => service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypeSms,
                target.App,
                phone: target.Phone,
                code: target.Code),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        var otp = await database.Context.Otps.AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        var account = await database.Context.Accounts.AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(OtpStatus.Sent, otp.Status);
        Assert.Equal(0, account.TotalLoginCount);
        Assert.Empty(await database.Context.RefreshTokens.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await database.Context.LoginHistories.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SmsFailure_WhenLoginHistoryInsertFails_RollsBackAttemptAndLockout()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var target = await SeedSmsLoginAsync(database.Context);
        await FailLoginHistoryInsertAsync(database.Context);
        var service = CreateSmsTokenIssuanceService(
            database.Context,
            CreateSmsValidator(database.Context));

        await Assert.ThrowsAsync<DbUpdateException>(() => service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypeSms,
                target.App,
                phone: target.Phone,
                code: "000000"),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        var otp = await database.Context.Otps.AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, otp.Attempts);
        Assert.Equal(DateTimeOffset.UnixEpoch, otp.LockoutUntil);
        Assert.Empty(await database.Context.LoginHistories.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SmsSuccess_CommitsConsumptionAuditLoginStateAndRefreshTokenTogether()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var target = await SeedSmsLoginAsync(database.Context);
        var service = CreateSmsTokenIssuanceService(
            database.Context,
            CreateSmsValidator(database.Context));

        var outcome = await service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypeSms,
                target.App,
                phone: target.Phone,
                code: target.Code),
            TestContext.Current.CancellationToken);

        Assert.True(outcome.IsSuccess);
        database.Context.ChangeTracker.Clear();
        Assert.Equal(OtpStatus.Consumed, await database.Context.Otps.AsNoTracking()
            .Select(otp => otp.Status)
            .SingleAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, await database.Context.Accounts.AsNoTracking()
            .Select(account => account.TotalLoginCount)
            .SingleAsync(TestContext.Current.CancellationToken));
        Assert.Single(await database.Context.RefreshTokens.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        var audit = await database.Context.LoginHistories.AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal("login_success", audit.EventType);
    }

    [Fact]
    public async Task SmsFailure_CommitsAttemptLockoutAndFailureAuditTogether()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var target = await SeedSmsLoginAsync(database.Context);
        var service = CreateSmsTokenIssuanceService(
            database.Context,
            CreateSmsValidator(database.Context));

        var outcome = await service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypeSms,
                target.App,
                phone: target.Phone,
                code: "000000"),
            TestContext.Current.CancellationToken);

        Assert.False(outcome.IsSuccess);
        database.Context.ChangeTracker.Clear();
        var otp = await database.Context.Otps.AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, otp.Attempts);
        Assert.True(otp.LockoutUntil > DateTimeOffset.UtcNow);
        var audit = await database.Context.LoginHistories.AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal("login_failure", audit.EventType);
    }

    [Fact]
    public async Task SmsFailure_AfterCodeMatch_CommitsConsumptionWithFailureAudit()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var target = await SeedSmsLoginAsync(database.Context);
        await database.Context.Accounts.ExecuteUpdateAsync(
            setters => setters.SetProperty(account => account.IsActive, false),
            TestContext.Current.CancellationToken);
        var service = CreateSmsTokenIssuanceService(
            database.Context,
            CreateSmsValidator(database.Context));

        var outcome = await service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypeSms,
                target.App,
                phone: target.Phone,
                code: target.Code),
            TestContext.Current.CancellationToken);

        Assert.False(outcome.IsSuccess);
        database.Context.ChangeTracker.Clear();
        Assert.Equal(OtpStatus.Consumed, await database.Context.Otps.AsNoTracking()
            .Select(otp => otp.Status)
            .SingleAsync(TestContext.Current.CancellationToken));
        var audit = await database.Context.LoginHistories.AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal("login_failure", audit.EventType);
        Assert.Empty(await database.Context.RefreshTokens.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SmsSuccess_WhenRequestIsCanceledBeforeAudit_RollsBackConsumption()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var target = await SeedSmsLoginAsync(database.Context);
        using var cancellation = new CancellationTokenSource();
        var auditService = new CancelingLoginAuditService(
            CreateAuditService(database.Context),
            cancellation);
        var service = CreateSmsTokenIssuanceService(
            database.Context,
            CreateSmsValidator(database.Context),
            auditService);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypeSms,
                target.App,
                phone: target.Phone,
                code: target.Code),
            cancellation.Token));

        database.Context.ChangeTracker.Clear();
        Assert.Equal(OtpStatus.Sent, await database.Context.Otps.AsNoTracking()
            .Select(otp => otp.Status)
            .SingleAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await database.Context.LoginHistories.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SmsSuccess_WhenSigningFails_DoesNotConsumeOtp()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var target = await SeedSmsLoginAsync(database.Context);
        var tokenService = new Mock<ITokenService>();
        tokenService.Setup(service => service.GenerateJwtToken(
                It.IsAny<List<Claim>>(),
                It.IsAny<Microsoft.IdentityModel.Tokens.RsaSecurityKey>(),
                It.IsAny<int>(),
                It.IsAny<string?>()))
            .Throws(new InvalidOperationException("Signing failed."));
        var service = CreateSmsTokenIssuanceService(
            database.Context,
            CreateSmsValidator(database.Context),
            tokenService: tokenService.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypeSms,
                target.App,
                phone: target.Phone,
                code: target.Code),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        Assert.Equal(OtpStatus.Sent, await database.Context.Otps.AsNoTracking()
            .Select(otp => otp.Status)
            .SingleAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await database.Context.LoginHistories.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SmsSuccess_WhenAdmissionProvisionFails_DoesNotConsumeOtp()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var target = await SeedSmsLoginAsync(database.Context, includeAdmission: false);
        target.App.SmsLoginMode = SmsLoginMode.AutoProvision;
        var admission = new Mock<ISmsAdmissionService>();
        admission.Setup(service => service.FindAsync(
                target.App.Id,
                target.Phone,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((SmsAdmission?)null);
        admission.Setup(service => service.ProvisionAsync(
                target.App,
                target.Phone,
                SmsAccessApprovalSource.AutoProvision,
                null,
                It.IsAny<CancellationToken>(),
                null))
            .ThrowsAsync(new InvalidOperationException("Provisioning failed."));
        var validator = CreateSmsValidator(database.Context, admission.Object);
        var service = CreateSmsTokenIssuanceService(database.Context, validator);

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypeSms,
                target.App,
                phone: target.Phone,
                code: target.Code),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        Assert.Equal(OtpStatus.Sent, await database.Context.Otps.AsNoTracking()
            .Select(otp => otp.Status)
            .SingleAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await database.Context.LoginHistories.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SmsSuccess_WhenTwoRequestsUseSameCode_OnlyOneReturnsTokens()
    {
        await using var database = await SharedSqliteTestDatabase.CreateAsync();
        SmsLoginTarget target;
        await using (var seedContext = database.CreateContext())
        {
            target = await SeedSmsLoginAsync(seedContext);
        }

        await using var firstContext = database.CreateContext();
        await using var secondContext = database.CreateContext();
        var barrier = new AsyncBarrier(2);
        var firstValidator = new CoordinatedIdentityValidator(
            CreateSmsValidator(firstContext), barrier);
        var secondValidator = new CoordinatedIdentityValidator(
            CreateSmsValidator(secondContext), barrier);
        var firstService = CreateSmsTokenIssuanceService(firstContext, firstValidator);
        var secondService = CreateSmsTokenIssuanceService(secondContext, secondValidator);
        var request = CreateIssuanceRequest(
            IdentityConstants.GrantTypeSms,
            target.App,
            phone: target.Phone,
            code: target.Code);

        var outcomes = await Task.WhenAll(
            firstService.IssueAsync(request, TestContext.Current.CancellationToken),
            secondService.IssueAsync(request, TestContext.Current.CancellationToken));

        Assert.Equal(1, outcomes.Count(outcome => outcome.IsSuccess));
        await using var assertionContext = database.CreateContext();
        Assert.Equal(OtpStatus.Consumed, await assertionContext.Otps.AsNoTracking()
            .Select(otp => otp.Status)
            .SingleAsync(TestContext.Current.CancellationToken));
        Assert.Single(await assertionContext.RefreshTokens.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        var audits = await assertionContext.LoginHistories.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.Single(audits, audit => audit.EventType == "login_success");
        Assert.Single(audits, audit => audit.EventType == "login_failure");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PasswordFailure_WhenLoginHistoryInsertFails_RollsBackAttemptIncrease(
        bool hasExistingAttempt)
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var passwordHasher = CreatePasswordHasher();
        var account = CreateAccount();
        database.Context.Accounts.Add(account);
        database.Context.PasswordCredentials.Add(CreatePasswordCredential(
            account.Id,
            "password-user",
            passwordHasher.HashPassword("correct-value")));
        if (hasExistingAttempt)
        {
            database.Context.LoginAttempts.Add(CreateLoginAttempt("password-user"));
        }
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        await FailLoginHistoryInsertAsync(database.Context);
        var loginAttemptRepository = new LoginAttemptRepository(database.Context);
        var validator = new PasswordValidator(
            new PasswordCredentialRepository(database.Context),
            new AccountRepository(database.Context),
            loginAttemptRepository,
            passwordHasher,
            NullLogger<PasswordValidator>.Instance);
        var service = CreateTokenIssuanceService(
            database.Context,
            validator,
            loginAttemptRepository);

        await Assert.ThrowsAsync<DbUpdateException>(() => service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypePassword,
                username: "password-user",
                password: "wrong-value"),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        var attempts = await database.Context.LoginAttempts
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken);
        if (hasExistingAttempt)
        {
            Assert.Equal(1, Assert.Single(attempts).FailedAttempts);
        }
        else
        {
            Assert.Empty(attempts);
        }
        Assert.Empty(await database.Context.LoginHistories
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task PasswordSuccess_WhenLoginHistoryInsertFails_RollsBackAttemptClear()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var passwordHasher = CreatePasswordHasher();
        var account = CreateAccount();
        database.Context.Accounts.Add(account);
        database.Context.PasswordCredentials.Add(CreatePasswordCredential(
            account.Id,
            "password-user",
            passwordHasher.HashPassword("correct-value")));
        database.Context.LoginAttempts.Add(CreateLoginAttempt("password-user"));
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        await FailLoginHistoryInsertAsync(database.Context);
        var loginAttemptRepository = new LoginAttemptRepository(database.Context);
        var validator = new PasswordValidator(
            new PasswordCredentialRepository(database.Context),
            new AccountRepository(database.Context),
            loginAttemptRepository,
            passwordHasher,
            NullLogger<PasswordValidator>.Instance);
        var service = CreateTokenIssuanceService(
            database.Context,
            validator,
            loginAttemptRepository);

        await Assert.ThrowsAsync<DbUpdateException>(() => service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypePassword,
                username: "password-user",
                password: "correct-value"),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        Assert.Equal(1, (await database.Context.LoginAttempts
            .AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken)).FailedAttempts);
        Assert.Equal(0, (await database.Context.Accounts
            .AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken)).TotalLoginCount);
        Assert.Empty(await database.Context.LoginHistories
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LdapFailure_WhenLoginHistoryInsertFails_RollsBackAttemptIncrease()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var app = CreateApp("ldap-app");
        app.LdapLoginMode = LdapLoginMode.AutoProvision;
        var directory = new LdapDirectoryOptions { Key = "corp" };
        var identity = new LdapDirectoryIdentity(
            directory.Key,
            Guid.NewGuid(),
            "alice@corp.example.test",
            "alice",
            true);
        var directoryClient = new Mock<ILdapDirectoryClient>();
        directoryClient.Setup(client => client.ResolveDirectory("alice")).Returns(directory);
        directoryClient.Setup(client => client.FindUserAsync(
                directory.Key,
                "alice",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(identity);
        directoryClient.Setup(client => client.ValidateCredentialsAsync(
                directory.Key,
                identity.UserPrincipalName,
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(LdapCredentialValidationResult.InvalidCredentials);
        var accountService = new Mock<ILdapAccountService>();
        accountService.Setup(service => service.GetCredentialByObjectGuidAsync(
                directory.Key,
                identity.ObjectGuid))
            .ReturnsAsync((LdapCredentialEntity?)null);
        await FailLoginHistoryInsertAsync(database.Context);
        var loginAttemptRepository = new LoginAttemptRepository(database.Context);
        var validator = new LdapValidator(
            new LdapOptions { Enabled = true },
            directoryClient.Object,
            accountService.Object,
            new AccountRepository(database.Context),
            loginAttemptRepository,
            AuthTestDoubles.AuthMetrics(),
            NullLogger<LdapValidator>.Instance);
        var service = CreateTokenIssuanceService(
            database.Context,
            validator,
            loginAttemptRepository);

        await Assert.ThrowsAsync<DbUpdateException>(() => service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypeLdap,
                app,
                username: "alice",
                password: "wrong-value"),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        Assert.Empty(await database.Context.LoginAttempts
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await database.Context.LoginHistories
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LdapSuccess_WhenLoginHistoryInsertFails_RollsBackAttemptClear()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var app = CreateApp("ldap-app");
        app.LdapLoginMode = LdapLoginMode.ManualApproval;
        var account = CreateAccount();
        var objectGuid = Guid.NewGuid();
        var credential = new LdapCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            DirectoryKey = "corp",
            ObjectGuid = objectGuid,
            UserPrincipalName = "alice@corp.example.test",
            SamAccountName = "alice"
        };
        var access = new AppLdapAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            LdapCredentialId = credential.Id,
            ApprovalSource = LdapAccessApprovalSource.Admin,
            IsActive = true
        };
        var attemptKey = $"ldap:corp:{objectGuid:N}";
        database.Context.Accounts.Add(account);
        database.Context.LoginAttempts.Add(CreateLoginAttempt(attemptKey));
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        await FailLoginHistoryInsertAsync(database.Context);
        var directory = new LdapDirectoryOptions { Key = "corp" };
        var directoryClient = new Mock<ILdapDirectoryClient>();
        directoryClient.Setup(client => client.ResolveDirectory("alice")).Returns(directory);
        directoryClient.Setup(client => client.ValidateCredentialsAsync(
                directory.Key,
                credential.UserPrincipalName,
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(LdapCredentialValidationResult.Success);
        var accountService = new Mock<ILdapAccountService>();
        accountService.Setup(service => service.FindCredentialByLoginAsync(directory.Key, "alice"))
            .ReturnsAsync(credential);
        accountService.Setup(service => service.GetAccessAsync(app.Id, credential.Id))
            .ReturnsAsync(access);
        var loginAttemptRepository = new LoginAttemptRepository(database.Context);
        var validator = new LdapValidator(
            new LdapOptions { Enabled = true },
            directoryClient.Object,
            accountService.Object,
            new AccountRepository(database.Context),
            loginAttemptRepository,
            AuthTestDoubles.AuthMetrics(),
            NullLogger<LdapValidator>.Instance);
        var service = CreateTokenIssuanceService(
            database.Context,
            validator,
            loginAttemptRepository);

        await Assert.ThrowsAsync<DbUpdateException>(() => service.IssueAsync(
            CreateIssuanceRequest(
                IdentityConstants.GrantTypeLdap,
                app,
                username: "alice",
                password: "valid-value"),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        Assert.Equal(attemptKey, (await database.Context.LoginAttempts
            .AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken)).Username);
        Assert.Empty(await database.Context.LoginHistories
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AdminPasswordFailure_WhenLoginHistoryInsertFails_RollsBackAttemptIncrease()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var passwordHasher = CreatePasswordHasher();
        var account = CreateAccount();
        database.Context.Accounts.Add(account);
        database.Context.PasswordCredentials.Add(CreatePasswordCredential(
            account.Id,
            "admin",
            passwordHasher.HashPassword("correct-value")));
        database.Context.LoginAttempts.Add(CreateLoginAttempt("admin"));
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        await FailLoginHistoryInsertAsync(database.Context);
        var loginAttemptRepository = new LoginAttemptRepository(database.Context);
        var validator = new PasswordValidator(
            new PasswordCredentialRepository(database.Context),
            new AccountRepository(database.Context),
            loginAttemptRepository,
            passwordHasher,
            NullLogger<PasswordValidator>.Instance);

        await Assert.ThrowsAsync<DbUpdateException>(() => CreateAdminController().Login(
            new AdminLoginRequest("admin", "wrong-value", false),
            new ValidatorFactory([validator], NullLogger<ValidatorFactory>.Instance),
            new AdminIdentityOptions { Username = "admin" },
            CreateAuditService(database.Context),
            loginAttemptRepository,
            new EfCoreUnitOfWork(database.Context),
            database.Context));

        database.Context.ChangeTracker.Clear();
        Assert.Equal(1, (await database.Context.LoginAttempts
            .AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken)).FailedAttempts);
        Assert.Empty(await database.Context.LoginHistories
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RemoveExchangeTrust_WhenConcurrentDeleteLoses_ReturnsNotFoundWithoutAudit()
    {
        await using var database = await SharedSqliteTestDatabase.CreateAsync();
        var acceptingApp = CreateApp("accepting-app");
        var sourceApp = CreateApp("source-app");
        await using (var seedContext = database.CreateContext())
        {
            seedContext.AppRegistrations.AddRange(acceptingApp, sourceApp);
            seedContext.AppExchangeTrusts.Add(new AppExchangeTrustEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = acceptingApp.Id,
                SourceAppRegistrationId = sourceApp.Id,
                CreatedAt = DateTimeOffset.UtcNow
            });
            await seedContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using var firstContext = database.CreateContext();
        await using var secondContext = database.CreateContext();
        var bothDeletesStaged = new AsyncBarrier(participantCount: 2);
        var firstSaveCompleted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var firstTask = CreateAdminController().RemoveExchangeTrust(
            acceptingApp.AppId,
            sourceApp.AppId,
            new AppRegistrationRepository(firstContext),
            new CoordinatedExchangeTrustRepository(firstContext, bothDeletesStaged),
            CreateAuditService(firstContext),
            new OrderedUnitOfWork(firstContext, Task.CompletedTask, firstSaveCompleted),
            firstContext,
            TestContext.Current.CancellationToken);
        var secondTask = CreateAdminController().RemoveExchangeTrust(
            acceptingApp.AppId,
            sourceApp.AppId,
            new AppRegistrationRepository(secondContext),
            new CoordinatedExchangeTrustRepository(secondContext, bothDeletesStaged),
            CreateAuditService(secondContext),
            new OrderedUnitOfWork(secondContext, firstSaveCompleted.Task),
            secondContext,
            TestContext.Current.CancellationToken);

        var results = await Task.WhenAll(firstTask, secondTask);

        Assert.IsType<OkObjectResult>(results[0]);
        Assert.IsType<NotFoundObjectResult>(results[1]);
        Assert.Empty(secondContext.ChangeTracker.Entries());

        await using var verificationContext = database.CreateContext();
        Assert.False(await verificationContext.AppExchangeTrusts
            .AnyAsync(TestContext.Current.CancellationToken));
        var audit = await verificationContext.AuditLogs
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal("app_exchange_trust_removed", audit.Action);
        Assert.Equal(acceptingApp.AppId, audit.TargetId);
        Assert.Contains(sourceApp.AppId, audit.BeforeSnapshot, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RevokeSmsUser_WhenCleanupDeletesTokenBeforeTheUpdate_StillRevokesAndAudits()
    {
        // CleanupWorker.RemoveExpiredAndRevokedAsync deletes expired-but-unrevoked rows, which the
        // revocation query also matches. Drop one such row just before the revoking UPDATE runs.
        var interceptor = new DeleteRowBeforeRefreshTokenUpdateInterceptor("sms-expired");
        await using var database = await SqliteTestDatabase.CreateAsync(interceptor);
        var targets = await SeedRevocationTargetsAsync(database.Context);

        var result = await CreateAdminController().RevokeSmsUser(
            targets.App.AppId,
            targets.UserLoginId,
            database.Context,
            CreateAuditService(database.Context),
            TestContext.Current.CancellationToken);

        Assert.IsType<OkObjectResult>(result);
        Assert.True(interceptor.Fired);

        database.Context.ChangeTracker.Clear();
        Assert.False(await database.Context.AppSmsAccesses
            .Select(access => access.IsActive)
            .SingleAsync(TestContext.Current.CancellationToken));
        Assert.False(await database.Context.RefreshTokens
            .AnyAsync(token => token.Id == targets.ExpiredSmsTokenId, TestContext.Current.CancellationToken));
        Assert.True(await database.Context.RefreshTokens
            .Where(token => token.Id == targets.ActiveSmsTokenId)
            .Select(token => token.IsRevoked)
            .SingleAsync(TestContext.Current.CancellationToken));
        var audit = await database.Context.AuditLogs.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal("app_sms_user_revoked", audit.Action);
        Assert.Equal(targets.App.AppId, audit.TargetId);
    }

    [Fact]
    public async Task RevokeSmsUser_WhenAuditInsertFails_RollsBackAccessAndTokenRevocation()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var targets = await SeedRevocationTargetsAsync(database.Context);
        await FailAuditLogInsertAsync(database.Context);

        await Assert.ThrowsAsync<DbUpdateException>(() => CreateAdminController().RevokeSmsUser(
            targets.App.AppId,
            targets.UserLoginId,
            database.Context,
            CreateAuditService(database.Context),
            TestContext.Current.CancellationToken));

        await AssertRevocationRolledBackAsync(database.Context, targets.ActiveSmsTokenId);
        Assert.True(await database.Context.AppSmsAccesses
            .Select(access => access.IsActive)
            .SingleAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RevokeWechatUser_WhenAuditInsertFails_RollsBackAccessAndTokenRevocation()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var targets = await SeedRevocationTargetsAsync(database.Context);
        await FailAuditLogInsertAsync(database.Context);

        await Assert.ThrowsAsync<DbUpdateException>(() => CreateAdminController().RevokeWechatUser(
            targets.App.AppId,
            targets.UserLoginId,
            database.Context,
            CreateAuditService(database.Context),
            TestContext.Current.CancellationToken));

        await AssertRevocationRolledBackAsync(database.Context, targets.ActiveWechatTokenId);
        Assert.True(await database.Context.AppWechatAccesses
            .Select(access => access.IsActive)
            .SingleAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RevokeLdapUser_WhenAuditInsertFails_RollsBackAccessAndTokenRevocation()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var targets = await SeedRevocationTargetsAsync(database.Context);
        await FailAuditLogInsertAsync(database.Context);

        await Assert.ThrowsAsync<DbUpdateException>(() => CreateAdminController().RevokeLdapUser(
            targets.App.AppId,
            targets.LdapCredentialId,
            database.Context,
            CreateAuditService(database.Context),
            TestContext.Current.CancellationToken));

        await AssertRevocationRolledBackAsync(database.Context, targets.ActiveLdapTokenId);
        Assert.True(await database.Context.AppLdapAccesses
            .Select(access => access.IsActive)
            .SingleAsync(TestContext.Current.CancellationToken));
    }

    private static async Task AssertRevocationRolledBackAsync(IdentityDbContext context, Guid tokenId)
    {
        context.ChangeTracker.Clear();
        Assert.False(await context.RefreshTokens
            .Where(token => token.Id == tokenId)
            .Select(token => token.IsRevoked)
            .SingleAsync(TestContext.Current.CancellationToken));
        Assert.False(await context.AuditLogs.AnyAsync(TestContext.Current.CancellationToken));
    }

    private static Task FailAuditLogInsertAsync(IdentityDbContext context) =>
        context.Database.ExecuteSqlRawAsync(
            """
            CREATE TRIGGER fail_audit_insert
            BEFORE INSERT ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit insert failed');
            END;
            """,
            TestContext.Current.CancellationToken);

    private static async Task<RevocationTargets> SeedRevocationTargetsAsync(IdentityDbContext context)
    {
        var account = CreateAccount();
        var app = CreateApp("revoke-app");
        var userLogin = new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            ProviderName = "Sms",
            ProviderNameNormalized = "sms",
            ProviderUserId = "+8613800000000"
        };
        var ldapCredential = new LdapCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            DirectoryKey = "corp",
            DirectoryKeyNormalized = "corp",
            ObjectGuid = Guid.NewGuid(),
            UserPrincipalName = "member@corp.example",
            UserPrincipalNameNormalized = "member@corp.example",
            SamAccountName = "member",
            SamAccountNameNormalized = "member",
            CreatedAt = DateTimeOffset.UtcNow
        };
        var now = DateTimeOffset.UtcNow;
        var activeSmsToken = CreateRefreshToken(account.Id, app.AppId, "sms-active", now.AddHours(1));
        activeSmsToken.SmsUserLoginId = userLogin.Id;
        var expiredSmsToken = CreateRefreshToken(account.Id, app.AppId, "sms-expired", now.AddHours(-1));
        expiredSmsToken.SmsUserLoginId = userLogin.Id;
        var activeWechatToken = CreateRefreshToken(account.Id, app.AppId, "wechat-active", now.AddHours(1));
        activeWechatToken.WechatUserLoginId = userLogin.Id;
        var activeLdapToken = CreateRefreshToken(account.Id, app.AppId, "ldap-active", now.AddHours(1));
        activeLdapToken.LdapCredentialId = ldapCredential.Id;

        context.Accounts.Add(account);
        context.AppRegistrations.Add(app);
        context.UserLogins.Add(userLogin);
        context.LdapCredentials.Add(ldapCredential);
        context.AppSmsAccesses.Add(new AppSmsAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            UserLoginId = userLogin.Id,
            ApprovalSource = SmsAccessApprovalSource.Admin,
            IsActive = true,
            CreatedAt = now
        });
        context.AppWechatAccesses.Add(new AppWechatAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            UserLoginId = userLogin.Id,
            ApprovalSource = WechatAccessApprovalSource.SelfBind,
            IsActive = true,
            CreatedAt = now
        });
        context.AppLdapAccesses.Add(new AppLdapAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            LdapCredentialId = ldapCredential.Id,
            ApprovalSource = LdapAccessApprovalSource.Admin,
            IsActive = true,
            CreatedAt = now
        });
        context.RefreshTokens.AddRange(
            activeSmsToken, expiredSmsToken, activeWechatToken, activeLdapToken);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();

        return new RevocationTargets(
            app,
            userLogin.Id,
            ldapCredential.Id,
            activeSmsToken.Id,
            expiredSmsToken.Id,
            activeWechatToken.Id,
            activeLdapToken.Id);
    }

    private static RefreshTokenEntity CreateRefreshToken(
        Guid accountId, string appId, string tokenValue, DateTimeOffset expiresAt) => new()
    {
        Id = Guid.NewGuid(),
        AccountId = accountId,
        AppId = appId,
        TokenValue = tokenValue,
        ExpiresAt = expiresAt,
        CreatedAt = DateTimeOffset.UtcNow,
        IsRevoked = false
    };

    private sealed record RevocationTargets(
        AppRegistrationEntity App,
        Guid UserLoginId,
        Guid LdapCredentialId,
        Guid ActiveSmsTokenId,
        Guid ExpiredSmsTokenId,
        Guid ActiveWechatTokenId,
        Guid ActiveLdapTokenId);

    /// <summary>
    /// Deletes one refresh token on the same connection immediately before the statement that
    /// revokes refresh tokens, reproducing a cleanup pass that removes a matched row after the
    /// request started. A tracked per-row update would report zero affected rows here and throw
    /// <see cref="DbUpdateConcurrencyException"/>.
    /// </summary>
    private sealed class DeleteRowBeforeRefreshTokenUpdateInterceptor : DbCommandInterceptor
    {
        private readonly string _tokenValue;
        private int _fired;

        public DeleteRowBeforeRefreshTokenUpdateInterceptor(string tokenValue) => _tokenValue = tokenValue;

        public bool Fired => Volatile.Read(ref _fired) == 1;

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            DeleteIfRevokingRefreshTokens(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        // A tracked per-row update is sent as "UPDATE ... RETURNING 1", which executes as a reader
        // rather than a non-query, so both paths have to be covered for the seam to hold whichever
        // shape the endpoint uses.
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            DeleteIfRevokingRefreshTokens(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void DeleteIfRevokingRefreshTokens(DbCommand command)
        {
            if (!command.CommandText.Contains("refresh_tokens", StringComparison.Ordinal) ||
                !command.CommandText.TrimStart().StartsWith("UPDATE", StringComparison.OrdinalIgnoreCase) ||
                Interlocked.Exchange(ref _fired, 1) != 0)
            {
                return;
            }

            using var delete = command.Connection!.CreateCommand();
            delete.Transaction = command.Transaction;
            delete.CommandText = "DELETE FROM refresh_tokens WHERE token_value = $token";
            var parameter = delete.CreateParameter();
            parameter.ParameterName = "$token";
            parameter.Value = _tokenValue;
            delete.Parameters.Add(parameter);
            delete.ExecuteNonQuery();
        }
    }

    private static AdminController CreateAdminController()
    {
        var controller = new AdminController(NullLogger<AdminController>.Instance);
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.20");
        httpContext.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, "admin")
        ], "Test"));
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        return controller;
    }

    private static AuditService CreateAuditService(IdentityDbContext context) =>
        new(new LoginHistoryRepository(context), new AuditLogRepository(context));

    private static AppRegistrationEntity CreateSmsApp()
    {
        var app = CreateApp("sms-app");
        app.SmsLoginMode = SmsLoginMode.AutoProvision;
        app.SmsProfileKey = "primary";
        return app;
    }

    private static (SmsCodeController Controller, Mock<ISmsSender> Sender) CreateSmsController(
        IdentityDbContext context,
        AppRegistrationEntity app,
        Action? onSend = null)
    {
        var options = new SmsOptions
        {
            OtpHmacKey = Convert.ToBase64String(
                Enumerable.Range(1, 32).Select(value => (byte)value).ToArray()),
            Profiles = new Dictionary<string, SmsProviderProfile>(StringComparer.OrdinalIgnoreCase)
            {
                ["primary"] = new() { Provider = "Test" }
            }
        };
        var sender = new Mock<ISmsSender>();
        sender.SetupGet(value => value.Provider).Returns("Test");
        sender.Setup(value => value.SendAsync(
                It.IsAny<SmsProviderProfile>(),
                It.IsAny<SmsVerificationMessage>(),
                It.IsAny<CancellationToken>()))
            .Callback<SmsProviderProfile, SmsVerificationMessage, CancellationToken>(
                (_, _, _) => onSend?.Invoke())
            .ReturnsAsync(new SmsSendResult("Test", "message-148"));
        var unitOfWork = new EfCoreUnitOfWork(context);
        var otpService = new DbOtpService(
            options,
            NullLogger<DbOtpService>.Instance,
            new OtpRepository(context),
            unitOfWork,
            new SmsSenderResolver([sender.Object], options));
        var controller = new SmsCodeController(
            otpService,
            new Mock<ISmsAdmissionService>().Object,
            CreateAuditService(context),
            unitOfWork,
            NullLogger<SmsCodeController>.Instance);
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.10");
        httpContext.Request.Headers.UserAgent = "audit-test-agent";
        httpContext.Items[IdentityHeaders.ValidatedApp] = app;
        httpContext.Items[CorrelationIdMiddleware.HttpContextItemsKey] = "correlation-148";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        return (controller, sender);
    }

    private static IPasswordHasher CreatePasswordHasher() =>
        new BCryptPasswordHasher(new PasswordHasherOptions { WorkFactor = 4 });

    private static AccountEntity CreateAccount() => new()
    {
        Id = Guid.NewGuid(),
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };

    private static PasswordCredentialEntity CreatePasswordCredential(
        Guid accountId,
        string username,
        string passwordHash) => new()
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = username,
            PasswordHash = passwordHash,
            CreatedAt = DateTimeOffset.UtcNow
        };

    private static LoginAttemptEntity CreateLoginAttempt(string username) => new()
    {
        Id = Guid.NewGuid(),
        Username = username,
        FailedAttempts = 1,
        LastAttemptAt = DateTimeOffset.UtcNow
    };

    private static Task FailLoginHistoryInsertAsync(IdentityDbContext context) =>
        context.Database.ExecuteSqlRawAsync(
            """
            CREATE TRIGGER fail_login_history_insert
            BEFORE INSERT ON login_histories
            BEGIN
                SELECT RAISE(ABORT, 'login history insert failed');
            END;
            """,
            TestContext.Current.CancellationToken);

    private static SmsOptions CreateSmsOptions() => new()
    {
        OtpHmacKey = Convert.ToBase64String(
            Enumerable.Range(1, 32).Select(value => (byte)value).ToArray()),
        MaxAttempts = 1,
        LockoutSeconds = 300
    };

    private static SmsValidator CreateSmsValidator(
        IdentityDbContext context,
        ISmsAdmissionService? admissionService = null)
    {
        var options = CreateSmsOptions();
        var otpService = new DbOtpService(
            options,
            NullLogger<DbOtpService>.Instance,
            new OtpRepository(context),
            new EfCoreUnitOfWork(context),
            new SmsSenderResolver([], options));
        return new SmsValidator(
            otpService,
            admissionService ?? new SmsAdmissionService(context),
            NullLogger<SmsValidator>.Instance,
            AuthTestDoubles.AuthMetrics(),
            options);
    }

    private static async Task<SmsLoginTarget> SeedSmsLoginAsync(
        IdentityDbContext context,
        bool includeAdmission = true)
    {
        const string phone = "+8613800138000";
        const string code = "123456";
        var app = CreateApp("sms-token-app");
        app.SmsLoginMode = SmsLoginMode.ManualApproval;
        var account = CreateAccount();
        var login = new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            ProviderName = IdentityConstants.AuthMethodSms,
            ProviderNameNormalized = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodSms),
            ProviderUserId = phone
        };
        context.AppRegistrations.Add(app);
        context.Accounts.Add(account);
        context.UserLogins.Add(login);
        if (includeAdmission)
        {
            context.AppSmsAccesses.Add(new AppSmsAccessEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = app.Id,
                UserLoginId = login.Id,
                ApprovalSource = SmsAccessApprovalSource.Admin,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            });
        }

        var now = DateTimeOffset.UtcNow;
        context.Otps.Add(new OtpEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            Phone = phone,
            CodeMac = ComputeOtpMac(app.Id, phone, code, CreateSmsOptions()),
            Status = OtpStatus.Sent,
            ExpiresAt = now.AddMinutes(5),
            LockoutUntil = DateTimeOffset.UnixEpoch,
            HourWindowStartedAt = now,
            DayWindowStartedAt = now,
            Provider = "Test",
            ProfileKey = "test",
            CreatedAt = now
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return new SmsLoginTarget(app, account, phone, code);
    }

    private static string ComputeOtpMac(
        Guid appRegistrationId,
        string phone,
        string code,
        SmsOptions options)
    {
        using var hmac = new HMACSHA256(options.DecodeHmacKey());
        return Convert.ToHexString(hmac.ComputeHash(
            Encoding.UTF8.GetBytes($"{appRegistrationId:N}|{phone}|{code}")));
    }

    private static TokenIssuanceRequest CreateIssuanceRequest(
        string grantType,
        AppRegistrationEntity? app = null,
        string? username = null,
        string? password = null,
        string? phone = null,
        string? code = null) => new(
        grantType,
        app ?? CreateApp("token-app"),
        Username: username,
        Password: password,
        Phone: phone,
        Code: code,
        ClientIp: "192.0.2.30",
            UserAgent: "audit-transaction-test",
            CorrelationId: "correlation-148");

    private static TokenIssuanceService CreateTokenIssuanceService(
        IdentityDbContext context,
        IIdentityValidator validator,
        ILoginAttemptRepository loginAttemptRepository,
        IRefreshTokenService? refreshTokenService = null,
        IAuditService? auditService = null,
        ITokenService? tokenService = null)
    {
        var accountRepository = new AccountRepository(context);
        return new TokenIssuanceService(
            AuthTestDoubles.KeyManager().Object,
            tokenService ?? AuthTestDoubles.TokenService().Object,
            new JwtOptions
            {
                Issuer = "https://issuer.example.test",
                Audience = "audit-tests",
                TokenExpirationHours = 1
            },
            refreshTokenService ?? AuthTestDoubles.RefreshTokenService().Object,
            new ClaimsResolver(NullLogger<ClaimsResolver>.Instance),
            new ValidatorFactory([validator], NullLogger<ValidatorFactory>.Instance),
            null,
            AuthTestDoubles.AuthMetrics(),
            auditService ?? CreateAuditService(context),
            new AccountLoginInfoService(accountRepository),
            accountRepository,
            loginAttemptRepository,
            new OtpRepository(context),
            new EfCoreUnitOfWork(context),
            context,
            new AdminIdentityOptions { Username = "bootstrap-admin" },
            NullLogger<TokenIssuanceService>.Instance);
    }

    private static TokenIssuanceService CreateSmsTokenIssuanceService(
        IdentityDbContext context,
        IIdentityValidator validator,
        IAuditService? auditService = null,
        ITokenService? tokenService = null) =>
        CreateTokenIssuanceService(
            context,
            validator,
            new LoginAttemptRepository(context),
            new RefreshTokenService(
                new RefreshTokenRepository(context),
                new RefreshTokenOptions { RefreshTokenExpirationDays = 7 }),
            auditService,
            tokenService);

    private sealed record SmsLoginTarget(
        AppRegistrationEntity App,
        AccountEntity Account,
        string Phone,
        string Code);

    private sealed class CoordinatedIdentityValidator(
        IIdentityValidator inner,
        AsyncBarrier barrier) : IIdentityValidator
    {
        public string GrantType => inner.GrantType;

        public async Task<ValidationResult> ValidateAsync(ValidationRequest request)
        {
            var result = await inner.ValidateAsync(request);
            await barrier.SignalAndWaitAsync(request.CancellationToken);
            return result;
        }
    }

    private sealed class CancelingLoginAuditService(
        IAuditService inner,
        CancellationTokenSource cancellation) : IAuditService
    {
        public Task RecordLoginAsync(
            Guid? accountId,
            string username,
            string authMethod,
            string eventType,
            string? clientIp,
            string? userAgent,
            string? failureReason = null,
            string? appId = null,
            string? correlationId = null,
            CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            return inner.RecordLoginAsync(
                accountId,
                username,
                authMethod,
                eventType,
                clientIp,
                userAgent,
                failureReason,
                appId,
                correlationId,
                cancellationToken);
        }

        public Task RecordActionAsync(
            string action,
            string targetType,
            string targetId,
            Guid? actorId,
            string? actorName,
            string? description,
            string? clientIp = null,
            string? correlationId = null,
            object? before = null,
            object? after = null,
            CancellationToken cancellationToken = default) =>
            inner.RecordActionAsync(
                action,
                targetType,
                targetId,
                actorId,
                actorName,
                description,
                clientIp,
                correlationId,
                before,
                after,
                cancellationToken);
    }

    private static AppRegistrationEntity CreateApp(string appId) => new()
    {
        Id = Guid.NewGuid(),
        AppId = appId,
        AppIdNormalized = IdentityValueNormalizer.Normalize(appId),
        AppName = appId,
        AppSecretHash = "not-used",
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };

    private sealed class AsyncBarrier
    {
        private readonly TaskCompletionSource _released = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _remaining;

        public AsyncBarrier(int participantCount) => _remaining = participantCount;

        public async Task SignalAndWaitAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Decrement(ref _remaining) == 0)
            {
                _released.TrySetResult();
            }

            await _released.Task.WaitAsync(cancellationToken);
        }
    }

    private sealed class CoordinatedExchangeTrustRepository : IAppExchangeTrustRepository
    {
        private readonly AppExchangeTrustRepository _inner;
        private readonly AsyncBarrier _barrier;

        public CoordinatedExchangeTrustRepository(IdentityDbContext context, AsyncBarrier barrier)
        {
            _inner = new AppExchangeTrustRepository(context);
            _barrier = barrier;
        }

        public Task<bool> IsTrustedSourceAsync(
            Guid appRegistrationId,
            string sourceAppId,
            CancellationToken cancellationToken = default) =>
            _inner.IsTrustedSourceAsync(appRegistrationId, sourceAppId, cancellationToken);

        public Task<IReadOnlyList<AppExchangeTrust>> ListSourcesAsync(
            Guid appRegistrationId,
            CancellationToken cancellationToken = default) =>
            _inner.ListSourcesAsync(appRegistrationId, cancellationToken);

        public Task<AppExchangeTrust> AddAsync(
            AppRegistrationEntity app,
            AppRegistrationEntity sourceApp,
            Guid? approvedBy,
            CancellationToken cancellationToken = default) =>
            _inner.AddAsync(app, sourceApp, approvedBy, cancellationToken);

        public async Task<bool> RemoveAsync(
            Guid appRegistrationId,
            Guid sourceAppRegistrationId,
            CancellationToken cancellationToken = default)
        {
            var removed = await _inner.RemoveAsync(
                appRegistrationId,
                sourceAppRegistrationId,
                cancellationToken);
            await _barrier.SignalAndWaitAsync(cancellationToken);
            return removed;
        }
    }

    private sealed class OrderedUnitOfWork : IUnitOfWork
    {
        private readonly IdentityDbContext _context;
        private readonly Task _waitBeforeSave;
        private readonly TaskCompletionSource? _saveCompleted;

        public OrderedUnitOfWork(
            IdentityDbContext context,
            Task waitBeforeSave,
            TaskCompletionSource? saveCompleted = null)
        {
            _context = context;
            _waitBeforeSave = waitBeforeSave;
            _saveCompleted = saveCompleted;
        }

        public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            await _waitBeforeSave.WaitAsync(cancellationToken);
            try
            {
                return await _context.SaveChangesAsync(cancellationToken);
            }
            finally
            {
                _saveCompleted?.TrySetResult();
            }
        }
    }

    private sealed class SqliteTestDatabase : IAsyncDisposable
    {
        private SqliteTestDatabase(SqliteConnection connection, IdentityDbContext context)
        {
            Connection = connection;
            Context = context;
        }

        private SqliteConnection Connection { get; }

        public IdentityDbContext Context { get; }

        public static async Task<SqliteTestDatabase> CreateAsync(IInterceptor? interceptor = null)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var builder = new DbContextOptionsBuilder<IdentityDbContext>().UseSqlite(connection);
            if (interceptor != null) builder.AddInterceptors(interceptor);
            var context = new IdentityDbContext(builder.Options);
            await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return new SqliteTestDatabase(connection, context);
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }

    private sealed class SharedSqliteTestDatabase : IAsyncDisposable
    {
        private readonly string _connectionString;
        private readonly SqliteConnection _keepAliveConnection;

        private SharedSqliteTestDatabase(string connectionString, SqliteConnection keepAliveConnection)
        {
            _connectionString = connectionString;
            _keepAliveConnection = keepAliveConnection;
        }

        public static async Task<SharedSqliteTestDatabase> CreateAsync()
        {
            var connectionString = $"Data Source=audit-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
            var keepAliveConnection = new SqliteConnection(connectionString);
            await keepAliveConnection.OpenAsync(TestContext.Current.CancellationToken);
            var database = new SharedSqliteTestDatabase(connectionString, keepAliveConnection);
            await using var context = database.CreateContext();
            await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return database;
        }

        public IdentityDbContext CreateContext() => new(
            new DbContextOptionsBuilder<IdentityDbContext>()
                .UseSqlite(_connectionString)
                .Options);

        public async ValueTask DisposeAsync() => await _keepAliveConnection.DisposeAsync();
    }
}
