using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using SignaCore.Host.Controllers;
using SignaCore.Host.Models;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

public class AdminControllerTests : IDisposable
{
    private readonly IdentityDbContext _dbContext;
    private readonly AdminController _controller;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly Mock<IAccountRepository> _accountRepoMock;
    private readonly Mock<IUnitOfWork> _unitOfWorkMock;
    private readonly Mock<IPasswordPolicy> _passwordPolicyMock;
    private readonly Mock<IPasswordHasher> _passwordHasherMock;
    private readonly Mock<IPasswordCredentialRepository> _passwordCredentialRepoMock;
    private readonly Mock<IUserLoginRepository> _userLoginRepoMock;
    private readonly Mock<IAppRegistrationRepository> _appRegRepoMock;
    private readonly Mock<IRefreshTokenRepository> _refreshTokenRepoMock;
    private readonly Mock<ILoginHistoryRepository> _loginHistoryRepoMock;
    private readonly Mock<IAuditLogRepository> _auditLogRepoMock;
    private readonly Mock<IIdentityValidator> _passwordValidatorMock;
    private readonly Mock<IAuthenticationService> _authServiceMock;
    private AdminIdentityOptions _adminIdentity;

    private static readonly Guid AdminId = Guid.NewGuid();
    private const string AdminName = "admin";
    private const string AdminScheme = "Cookies";
    private static readonly CallbackUrlValidator CallbackValidator = new();

    private static readonly JwtOptions TestJwtOptions = new()
    {
        Issuer = "TestIssuer",
        Audience = "TestAudience",
        TokenExpirationHours = 2
    };

    public AdminControllerTests()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        _dbContext = new IdentityDbContext(options);

        _auditServiceMock = new Mock<IAuditService>();
        _accountRepoMock = new Mock<IAccountRepository>();
        _unitOfWorkMock = new Mock<IUnitOfWork>();
        _unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        _passwordPolicyMock = new Mock<IPasswordPolicy>();
        _passwordHasherMock = new Mock<IPasswordHasher>();
        _passwordCredentialRepoMock = new Mock<IPasswordCredentialRepository>();
        _userLoginRepoMock = new Mock<IUserLoginRepository>();
        _appRegRepoMock = new Mock<IAppRegistrationRepository>();
        _refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        _loginHistoryRepoMock = new Mock<ILoginHistoryRepository>();
        _auditLogRepoMock = new Mock<IAuditLogRepository>();
        _passwordValidatorMock = new Mock<IIdentityValidator>();
        _passwordValidatorMock.SetupGet(v => v.GrantType).Returns(IdentityConstants.GrantTypePassword);

        _authServiceMock = new Mock<IAuthenticationService>();
        _authServiceMock.Setup(a => a.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
            .Returns(Task.CompletedTask);
        _authServiceMock.Setup(a => a.SignOutAsync(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<AuthenticationProperties>()))
            .Returns(Task.CompletedTask);

        _adminIdentity = new AdminIdentityOptions { Username = AdminName };

        _controller = new AdminController(NullLogger<AdminController>.Instance);
        var httpContext = new DefaultHttpContext
        {
            Connection = { RemoteIpAddress = IPAddress.Parse("127.0.0.1") }
        };
        var services = new ServiceCollection();
        services.AddSingleton(_authServiceMock.Object);
        httpContext.RequestServices = services.BuildServiceProvider();
        _controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    private void SetAdminUser()
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, AdminId.ToString()),
            new(ClaimTypes.Name, AdminName)
        };
        _controller.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
    }

    private AdminIdentityOptions CreateAdminIdentity() => _adminIdentity;

    private ValidatorFactory CreateValidatorFactory()
    {
        return new ValidatorFactory(new[] { _passwordValidatorMock.Object }, NullLogger<ValidatorFactory>.Instance);
    }

    #region Login

    [Fact]
    public async Task Login_WithEmptyUsername_ReturnsBadRequest()
    {
        var result = await _controller.Login(
            new AdminLoginRequest("", "pwd", false),
            CreateValidatorFactory(), CreateAdminIdentity(), _auditServiceMock.Object, _unitOfWorkMock.Object);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.IsType<ErrorResponse>(bad.Value);
        _passwordValidatorMock.Verify(v => v.ValidateAsync(It.IsAny<ValidationRequest>()), Times.Never);
    }

    [Fact]
    public async Task Login_WithEmptyPassword_ReturnsBadRequest()
    {
        var result = await _controller.Login(
            new AdminLoginRequest("user", "", false),
            CreateValidatorFactory(), CreateAdminIdentity(), _auditServiceMock.Object, _unitOfWorkMock.Object);

        Assert.IsType<BadRequestObjectResult>(result);
        _passwordValidatorMock.Verify(v => v.ValidateAsync(It.IsAny<ValidationRequest>()), Times.Never);
    }

    [Fact]
    public async Task Login_WithWhitespaceCredentials_ReturnsBadRequest()
    {
        var result = await _controller.Login(
            new AdminLoginRequest("   ", "   ", false),
            CreateValidatorFactory(), CreateAdminIdentity(), _auditServiceMock.Object, _unitOfWorkMock.Object);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Login_WhenValidationFails_Returns401AndRecordsAudit()
    {
        _passwordValidatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Failure("bad credentials"));

        var result = await _controller.Login(
            new AdminLoginRequest("user", "pwd", false),
            CreateValidatorFactory(), CreateAdminIdentity(), _auditServiceMock.Object, _unitOfWorkMock.Object);

        var status = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, status.StatusCode);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            null, "user", "admin_login", "login_failure",
            It.IsAny<string?>(), It.IsAny<string?>(), "bad credentials",
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Once);
        _unitOfWorkMock.Verify(
            unitOfWork => unitOfWork.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Login_WhenValidationSucceedsButNotBootstrapAdmin_Returns403AndRecordsAudit()
    {
        var account = new AccountEntity { Id = Guid.NewGuid() };
        _passwordValidatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Success(account, IdentityConstants.AuthMethodPassword, displayName: "nonadmin"));

        var result = await _controller.Login(
            new AdminLoginRequest("nonadmin", "pwd", false),
            CreateValidatorFactory(), CreateAdminIdentity(), _auditServiceMock.Object, _unitOfWorkMock.Object);

        var status = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, status.StatusCode);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            account.Id, "nonadmin", "admin_login", "login_failure",
            It.IsAny<string?>(), It.IsAny<string?>(), "bootstrap_admin_required",
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Once);
        _authServiceMock.Verify(a => a.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Never);
    }

    [Fact]
    public async Task Login_WhenBootstrapUsernameEmpty_RefusesAllUsers()
    {
        _adminIdentity = new AdminIdentityOptions { Username = string.Empty };
        var account = new AccountEntity { Id = Guid.NewGuid() };
        _passwordValidatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Success(account, IdentityConstants.AuthMethodPassword, displayName: AdminName));

        var result = await _controller.Login(
            new AdminLoginRequest(AdminName, "pwd", true),
            CreateValidatorFactory(), CreateAdminIdentity(), _auditServiceMock.Object, _unitOfWorkMock.Object);

        var status = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, status.StatusCode);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            account.Id, AdminName, "admin_login", "login_failure",
            It.IsAny<string?>(), It.IsAny<string?>(), "bootstrap_admin_required",
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Once);
        _authServiceMock.Verify(a => a.SignInAsync(It.IsAny<HttpContext>(), AdminScheme, It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Never);
    }

    [Fact]
    public async Task Login_WithBootstrapAdmin_SignsInAndReturnsSession()
    {
        var account = new AccountEntity { Id = Guid.NewGuid() };
        _passwordValidatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Success(account, IdentityConstants.AuthMethodPassword, displayName: AdminName));

        var result = await _controller.Login(
            new AdminLoginRequest(AdminName, "pwd", false),
            CreateValidatorFactory(), CreateAdminIdentity(), _auditServiceMock.Object, _unitOfWorkMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminSessionResponse>(ok.Value);
        Assert.Equal(account.Id.ToString(), response.AccountId);
        Assert.Equal(AdminName, response.Username);
        Assert.True(response.IsAuthenticated);
        _authServiceMock.Verify(a => a.SignInAsync(It.IsAny<HttpContext>(), AdminScheme, It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Once);
    }

    [Fact]
    public async Task Login_WhenDisplayNameNull_UsesRequestUsername()
    {
        var account = new AccountEntity { Id = Guid.NewGuid() };
        _passwordValidatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Success(account, IdentityConstants.AuthMethodPassword, displayName: null));

        var result = await _controller.Login(
            new AdminLoginRequest(AdminName, "pwd", false),
            CreateValidatorFactory(), CreateAdminIdentity(), _auditServiceMock.Object, _unitOfWorkMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminSessionResponse>(ok.Value);
        Assert.Equal(AdminName, response.Username);
        Assert.True(response.IsAuthenticated);
    }

    #endregion

    #region GetCurrentSession

    [Fact]
    public void GetCurrentSession_ReturnsClaimsFromUser()
    {
        SetAdminUser();
        var result = _controller.GetCurrentSession();

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminSessionResponse>(ok.Value);
        Assert.Equal(AdminId.ToString(), response.AccountId);
        Assert.Equal(AdminName, response.Username);
        Assert.True(response.IsAuthenticated);
    }

    #endregion

    #region Logout

    [Fact]
    public async Task Logout_SignsOutAndRecordsAudit()
    {
        SetAdminUser();

        var result = await _controller.Logout(_auditServiceMock.Object, _unitOfWorkMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<OperationResponse>(ok.Value);
        Assert.True(response.Success);
        _authServiceMock.Verify(a => a.SignOutAsync(It.IsAny<HttpContext>(), AdminScheme, It.IsAny<AuthenticationProperties>()), Times.Once);
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            "admin_logout", "Session", AdminId.ToString(),
            AdminId, AdminName, "Admin logged out", It.IsAny<string?>(),
            It.IsAny<string?>(), null, null), Times.Once);
        _unitOfWorkMock.Verify(
            unitOfWork => unitOfWork.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Logout_WithoutIdentity_RecordsUnknownActor()
    {
        // No user set - GetAdminIdentity returns (null, null)
        var result = await _controller.Logout(_auditServiceMock.Object, _unitOfWorkMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.True(Assert.IsType<OperationResponse>(ok.Value).Success);
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            "admin_logout", "Session", "unknown",
            null, null, "Admin logged out", It.IsAny<string?>(),
            It.IsAny<string?>(), null, null), Times.Once);
    }

    #endregion

    #region GetUsers

    [Fact]
    public async Task GetUsers_ReturnsPagedAccounts()
    {
        var acc1 = new AccountEntity { Id = Guid.NewGuid(), Nickname = "Alice", IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        var acc2 = new AccountEntity { Id = Guid.NewGuid(), Nickname = "Bob", IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        _dbContext.Accounts.AddRange(acc1, acc2);
        _dbContext.PasswordCredentials.Add(new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = acc1.Id, Username = "alice", PasswordHash = "h", CreatedAt = DateTimeOffset.UtcNow });
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await _controller.GetUsers(null, null, null, null, new UserQueryService(_dbContext));

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<UserListItemResponse>>(ok.Value);
        Assert.Equal(2, response.Total);
        Assert.Equal(2, response.Items.Count);
    }

    [Fact]
    public async Task GetUsers_HasPassword_ReflectsPasswordCredential()
    {
        var passwordAccount = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        var phoneAccount = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        _dbContext.Accounts.AddRange(passwordAccount, phoneAccount);
        _dbContext.PasswordCredentials.Add(new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = passwordAccount.Id, Username = "alice", PasswordHash = "h", CreatedAt = DateTimeOffset.UtcNow });
        _dbContext.UserLogins.Add(new UserLoginEntity { Id = Guid.NewGuid(), AccountId = phoneAccount.Id, ProviderName = IdentityConstants.AuthMethodSms, ProviderUserId = "13800001234" });
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await _controller.GetUsers(null, null, null, null, new UserQueryService(_dbContext));

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<UserListItemResponse>>(ok.Value);
        Assert.Equal(2, response.Items.Count);
        var passwordItem = Assert.Single(response.Items, i => i.UserId == passwordAccount.Id.ToString());
        Assert.True(passwordItem.HasPassword);
        var phoneItem = Assert.Single(response.Items, i => i.UserId == phoneAccount.Id.ToString());
        Assert.False(phoneItem.HasPassword);
        // Phone-only accounts fall back to the phone number as Username; type must not be derived from it.
        Assert.Equal("13800001234", phoneItem.Username);
    }

    [Fact]
    public async Task GetUsers_WithUsernameFilter_ReturnsMatches()
    {
        var acc1 = new AccountEntity { Id = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow };
        var acc2 = new AccountEntity { Id = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow };
        _dbContext.Accounts.AddRange(acc1, acc2);
        _dbContext.PasswordCredentials.Add(new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = acc1.Id, Username = "alice", PasswordHash = "h", CreatedAt = DateTimeOffset.UtcNow });
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await _controller.GetUsers("alice", null, null, null, new UserQueryService(_dbContext));

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<UserListItemResponse>>(ok.Value);
        Assert.Equal(1, response.Total);
        Assert.Equal("alice", response.Items[0].Username);
    }

    [Fact]
    public async Task GetUsers_WithRemarkFilter_ReturnsMatches()
    {
        var acc1 = new AccountEntity { Id = Guid.NewGuid(), Remark = "VIP customer", CreatedAt = DateTimeOffset.UtcNow };
        var acc2 = new AccountEntity { Id = Guid.NewGuid(), Remark = "regular", CreatedAt = DateTimeOffset.UtcNow };
        _dbContext.Accounts.AddRange(acc1, acc2);
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await _controller.GetUsers("VIP", null, null, null, new UserQueryService(_dbContext));

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<UserListItemResponse>>(ok.Value);
        Assert.Equal(1, response.Total);
    }

    [Fact]
    public async Task GetUsers_WithPhoneFilter_ReturnsMatches()
    {
        var acc1 = new AccountEntity { Id = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow };
        _dbContext.Accounts.Add(acc1);
        _dbContext.UserLogins.Add(new UserLoginEntity { Id = Guid.NewGuid(), AccountId = acc1.Id, ProviderName = IdentityConstants.AuthMethodSms, ProviderUserId = "13800001234" });
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await _controller.GetUsers(null, "1380000", null, null, new UserQueryService(_dbContext));

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<UserListItemResponse>>(ok.Value);
        Assert.Equal(1, response.Total);
        Assert.Equal("13800001234", response.Items[0].Phone);
    }

    [Fact]
    public async Task GetUsers_WithCustomPaging_AppliesPaging()
    {
        for (var i = 0; i < 5; i++)
        {
            _dbContext.Accounts.Add(new AccountEntity { Id = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow.AddSeconds(i) });
        }
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await _controller.GetUsers(null, null, 2, 2, new UserQueryService(_dbContext));

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<UserListItemResponse>>(ok.Value);
        Assert.Equal(5, response.Total);
        Assert.Equal(2, response.Items.Count);
        Assert.Equal(2, response.Page);
    }

    [Fact]
    public async Task GetUsers_WithInvalidPage_DefaultsToOne()
    {
        _dbContext.Accounts.Add(new AccountEntity { Id = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow });
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await _controller.GetUsers(null, null, 0, 10, new UserQueryService(_dbContext));

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<UserListItemResponse>>(ok.Value);
        Assert.Equal(1, response.Page);
    }

    [Fact]
    public async Task GetUsers_PageSizeCappedAt100()
    {
        _dbContext.Accounts.Add(new AccountEntity { Id = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow });
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await _controller.GetUsers(null, null, 1, 500, new UserQueryService(_dbContext));

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<UserListItemResponse>>(ok.Value);
        Assert.Equal(100, response.PageSize);
    }

    [Fact]
    public async Task GetUsers_WithNoDisplayName_FallsBackToIdPrefix()
    {
        var acc = new AccountEntity { Id = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow };
        _dbContext.Accounts.Add(acc);
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await _controller.GetUsers(null, null, null, null, new UserQueryService(_dbContext));

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<UserListItemResponse>>(ok.Value);
        Assert.Equal(acc.Id.ToString()[..8], response.Items[0].DisplayName);
    }

    #endregion

    #region CreateUser

    [Fact]
    public async Task CreateUser_WithEmptyUsername_ReturnsBadRequest()
    {
        SetAdminUser();
        var result = await _controller.CreateUser(
            new AdminCreateUserRequest("", "Password1", null, null, null),
            _passwordPolicyMock.Object, _passwordHasherMock.Object,
            _accountRepoMock.Object, _passwordCredentialRepoMock.Object,
            _unitOfWorkMock.Object, _auditServiceMock.Object);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task CreateUser_WithEmptyPassword_ReturnsBadRequest()
    {
        SetAdminUser();
        var result = await _controller.CreateUser(
            new AdminCreateUserRequest("user", "", null, null, null),
            _passwordPolicyMock.Object, _passwordHasherMock.Object,
            _accountRepoMock.Object, _passwordCredentialRepoMock.Object,
            _unitOfWorkMock.Object, _auditServiceMock.Object);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task CreateUser_WhenPasswordPolicyFails_ReturnsBadRequest()
    {
        SetAdminUser();
        var policyError = "too weak";
        _passwordPolicyMock.Setup(p => p.Validate(It.IsAny<string>(), out policyError))
            .Returns(false);

        var result = await _controller.CreateUser(
            new AdminCreateUserRequest("user", "weak", null, null, null),
            _passwordPolicyMock.Object, _passwordHasherMock.Object,
            _accountRepoMock.Object, _passwordCredentialRepoMock.Object,
            _unitOfWorkMock.Object, _auditServiceMock.Object);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        var err = Assert.IsType<ErrorResponse>(bad.Value);
        Assert.Equal("too weak", err.Message);
    }

    [Fact]
    public async Task CreateUser_WhenUsernameExists_ReturnsBadRequest()
    {
        SetAdminUser();
        var noError = string.Empty;
        _passwordPolicyMock.Setup(p => p.Validate(It.IsAny<string>(), out noError))
            .Returns(true);
        _passwordCredentialRepoMock.Setup(r => r.ExistsByUsernameAsync("existing")).ReturnsAsync(true);

        var result = await _controller.CreateUser(
            new AdminCreateUserRequest("existing", "Password1", null, null, null),
            _passwordPolicyMock.Object, _passwordHasherMock.Object,
            _accountRepoMock.Object, _passwordCredentialRepoMock.Object,
            _unitOfWorkMock.Object, _auditServiceMock.Object);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("already exists", Assert.IsType<ErrorResponse>(bad.Value).Message);
    }

    [Fact]
    public async Task CreateUser_WithValidInput_CreatesAccountAndRecordsAudit()
    {
        SetAdminUser();
        var noError = string.Empty;
        _passwordPolicyMock.Setup(p => p.Validate(It.IsAny<string>(), out noError))
            .Returns(true);
        _passwordCredentialRepoMock.Setup(r => r.ExistsByUsernameAsync(It.IsAny<string>())).ReturnsAsync(false);
        _passwordHasherMock.Setup(h => h.HashPassword("Password1")).Returns("hashed");
        _accountRepoMock.Setup(r => r.AddAsync(It.IsAny<AccountEntity>())).Returns(Task.CompletedTask).Verifiable();
        _passwordCredentialRepoMock.Setup(r => r.AddAsync(It.IsAny<PasswordCredentialEntity>())).Returns(Task.CompletedTask).Verifiable();

        var result = await _controller.CreateUser(
            new AdminCreateUserRequest("newuser", "Password1", "Display", "remark", "nick"),
            _passwordPolicyMock.Object, _passwordHasherMock.Object,
            _accountRepoMock.Object, _passwordCredentialRepoMock.Object,
            _unitOfWorkMock.Object, _auditServiceMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminCreateUserResponse>(ok.Value);
        Assert.Equal("newuser", response.Username);
        Assert.Equal("Display", response.DisplayName);
        Assert.Equal("remark", response.Remark);
        Assert.Equal("nick", response.Nickname);
        Assert.True(response.IsActive);
        _accountRepoMock.Verify();
        _passwordCredentialRepoMock.Verify();
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            "account_created", "Account", It.IsAny<string>(),
            AdminId, AdminName, It.IsAny<string>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<object?>()), Times.Once);
    }

    [Fact]
    public async Task CreateUser_WithoutDisplayName_UsesUsername()
    {
        SetAdminUser();
        var noError = string.Empty;
        _passwordPolicyMock.Setup(p => p.Validate(It.IsAny<string>(), out noError))
            .Returns(true);
        _passwordCredentialRepoMock.Setup(r => r.ExistsByUsernameAsync(It.IsAny<string>())).ReturnsAsync(false);
        _passwordHasherMock.Setup(h => h.HashPassword(It.IsAny<string>())).Returns("hashed");

        var result = await _controller.CreateUser(
            new AdminCreateUserRequest("newuser", "Password1", null, null, null),
            _passwordPolicyMock.Object, _passwordHasherMock.Object,
            _accountRepoMock.Object, _passwordCredentialRepoMock.Object,
            _unitOfWorkMock.Object, _auditServiceMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminCreateUserResponse>(ok.Value);
        Assert.Equal("newuser", response.DisplayName);
    }

    #endregion

    #region CreatePhoneUser

    [Fact]
    public async Task CreatePhoneUser_WithEmptyPhone_ReturnsBadRequest()
    {
        SetAdminUser();
        var result = await _controller.CreatePhoneUser(
            new AdminCreatePhoneUserRequest("", null, null, null),
            _accountRepoMock.Object, _userLoginRepoMock.Object,
            _unitOfWorkMock.Object, _auditServiceMock.Object);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task CreatePhoneUser_WhenPhoneExists_ReturnsBadRequest()
    {
        SetAdminUser();
        _userLoginRepoMock.Setup(r => r.GetBySmsPhoneAsync("+8613800001234"))
            .ReturnsAsync(new UserLoginEntity());

        var result = await _controller.CreatePhoneUser(
            new AdminCreatePhoneUserRequest("13800001234", null, null, null),
            _accountRepoMock.Object, _userLoginRepoMock.Object,
            _unitOfWorkMock.Object, _auditServiceMock.Object);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("already registered", Assert.IsType<ErrorResponse>(bad.Value).Message);
    }

    [Fact]
    public async Task CreatePhoneUser_WithValidPhone_CreatesAccountAndRecordsAudit()
    {
        SetAdminUser();
        _userLoginRepoMock.Setup(r => r.GetBySmsPhoneAsync(It.IsAny<string>())).ReturnsAsync((UserLoginEntity?)null);
        _accountRepoMock.Setup(r => r.AddAsync(It.IsAny<AccountEntity>())).Returns(Task.CompletedTask).Verifiable();
        _userLoginRepoMock.Setup(r => r.AddAsync(It.IsAny<UserLoginEntity>())).Returns(Task.CompletedTask).Verifiable();

        var result = await _controller.CreatePhoneUser(
            new AdminCreatePhoneUserRequest("13800001234", "Display", "remark", "nick"),
            _accountRepoMock.Object, _userLoginRepoMock.Object,
            _unitOfWorkMock.Object, _auditServiceMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminCreateUserResponse>(ok.Value);
        Assert.Equal("+8613800001234", response.Username);
        Assert.Equal("Display", response.DisplayName);
        Assert.Equal("remark", response.Remark);
        Assert.Equal("nick", response.Nickname);
        _accountRepoMock.Verify();
        _userLoginRepoMock.Verify();
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            "account_created", "Account", It.IsAny<string>(),
            AdminId, AdminName, It.IsAny<string>(), It.IsAny<string?>(),
            It.IsAny<string?>(), null, It.IsAny<object?>()), Times.Once);
    }

    #endregion

    #region UpdateUserRemark

    [Fact]
    public async Task UpdateUserRemark_WhenUserNotFound_ReturnsNotFound()
    {
        SetAdminUser();
        _accountRepoMock.Setup(r => r.GetByIdAsync(It.IsAny<Guid>())).ReturnsAsync((AccountEntity?)null);

        var result = await _controller.UpdateUserRemark(Guid.NewGuid(),
            new AdminUpdateRemarkRequest("remark"), _accountRepoMock.Object, _unitOfWorkMock.Object);

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task UpdateUserRemark_WithValidUser_UpdatesAndSaves()
    {
        SetAdminUser();
        var account = new AccountEntity { Id = Guid.NewGuid() };
        _accountRepoMock.Setup(r => r.GetByIdAsync(account.Id)).ReturnsAsync(account);
        _accountRepoMock.Setup(r => r.UpdateAsync(account)).Returns(Task.CompletedTask).Verifiable();

        var result = await _controller.UpdateUserRemark(account.Id,
            new AdminUpdateRemarkRequest("new remark"), _accountRepoMock.Object, _unitOfWorkMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.True(Assert.IsType<OperationResponse>(ok.Value).Success);
        Assert.Equal("new remark", account.Remark);
        _accountRepoMock.Verify();
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task UpdateUserRemark_WithWhitespaceRemark_SetsTrimmedValue()
    {
        SetAdminUser();
        var account = new AccountEntity { Id = Guid.NewGuid() };
        _accountRepoMock.Setup(r => r.GetByIdAsync(account.Id)).ReturnsAsync(account);

        var result = await _controller.UpdateUserRemark(account.Id,
            new AdminUpdateRemarkRequest("  spaced  "), _accountRepoMock.Object, _unitOfWorkMock.Object);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal("spaced", account.Remark);
    }

    #endregion

    #region UpdateUserNickname

    [Fact]
    public async Task UpdateUserNickname_WhenUserNotFound_ReturnsNotFound()
    {
        SetAdminUser();
        _accountRepoMock.Setup(r => r.GetByIdAsync(It.IsAny<Guid>())).ReturnsAsync((AccountEntity?)null);

        var result = await _controller.UpdateUserNickname(Guid.NewGuid(),
            new AdminUpdateNicknameRequest("nick"), _accountRepoMock.Object, _unitOfWorkMock.Object);

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task UpdateUserNickname_WithValidNickname_UpdatesAndSaves()
    {
        SetAdminUser();
        var account = new AccountEntity { Id = Guid.NewGuid() };
        _accountRepoMock.Setup(r => r.GetByIdAsync(account.Id)).ReturnsAsync(account);

        var result = await _controller.UpdateUserNickname(account.Id,
            new AdminUpdateNicknameRequest("NewNick"), _accountRepoMock.Object, _unitOfWorkMock.Object);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal("NewNick", account.Nickname);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task UpdateUserNickname_WithWhitespaceNickname_SetsNull()
    {
        SetAdminUser();
        var account = new AccountEntity { Id = Guid.NewGuid(), Nickname = "old" };
        _accountRepoMock.Setup(r => r.GetByIdAsync(account.Id)).ReturnsAsync(account);

        var result = await _controller.UpdateUserNickname(account.Id,
            new AdminUpdateNicknameRequest("   "), _accountRepoMock.Object, _unitOfWorkMock.Object);

        Assert.IsType<OkObjectResult>(result);
        Assert.Null(account.Nickname);
    }

    #endregion

    #region UpdateUserStatus

    [Fact]
    public async Task UpdateUserStatus_WhenUserNotFound_ReturnsNotFound()
    {
        SetAdminUser();
        _accountRepoMock.Setup(r => r.GetByIdAsync(It.IsAny<Guid>())).ReturnsAsync((AccountEntity?)null);

        var result = await _controller.UpdateUserStatus(Guid.NewGuid(),
            new AdminUpdateStatusRequest(true), _accountRepoMock.Object, _unitOfWorkMock.Object, _auditServiceMock.Object);

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task UpdateUserStatus_WhenEnabling_RecordsEnabledAudit()
    {
        SetAdminUser();
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = false };
        _accountRepoMock.Setup(r => r.GetByIdAsync(account.Id)).ReturnsAsync(account);

        var result = await _controller.UpdateUserStatus(account.Id,
            new AdminUpdateStatusRequest(true), _accountRepoMock.Object, _unitOfWorkMock.Object, _auditServiceMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<OperationResponse>(ok.Value);
        Assert.Contains("enabled", response.Message);
        Assert.True(account.IsActive);
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            "account_enabled", "Account", account.Id.ToString(),
            AdminId, AdminName, It.IsAny<string>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<object?>()), Times.Once);
    }

    [Fact]
    public async Task UpdateUserStatus_WhenDisabling_RecordsDisabledAudit()
    {
        SetAdminUser();
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        _accountRepoMock.Setup(r => r.GetByIdAsync(account.Id)).ReturnsAsync(account);

        var result = await _controller.UpdateUserStatus(account.Id,
            new AdminUpdateStatusRequest(false), _accountRepoMock.Object, _unitOfWorkMock.Object, _auditServiceMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<OperationResponse>(ok.Value);
        Assert.Contains("disabled", response.Message);
        Assert.False(account.IsActive);
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            "account_disabled", "Account", account.Id.ToString(),
            AdminId, AdminName, It.IsAny<string>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<object?>()), Times.Once);
    }

    #endregion

    #region GetApps

    [Fact]
    public async Task GetApps_ReturnsAllAppsOrderedByCreatedAtDesc()
    {
        var older = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "old",
            AppName = "Old",
            CreatedAt = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)
        };
        var newer = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "new",
            AppName = "New",
            CreatedAt = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero)
        };
        _dbContext.AppRegistrations.AddRange(older, newer);
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await _controller.GetApps(_dbContext, TestJwtOptions);

        var ok = Assert.IsType<OkObjectResult>(result);
        var list = Assert.IsAssignableFrom<IReadOnlyList<AdminAppListItemResponse>>(ok.Value);
        Assert.Equal(2, list.Count);
        Assert.Equal("new", list[0].AppId);
        Assert.Equal("old", list[1].AppId);
    }

    [Fact]
    public async Task GetApps_WhenNoApps_ReturnsEmptyList()
    {
        var result = await _controller.GetApps(_dbContext, TestJwtOptions);

        var ok = Assert.IsType<OkObjectResult>(result);
        var list = Assert.IsAssignableFrom<IReadOnlyList<AdminAppListItemResponse>>(ok.Value);
        Assert.Empty(list);
    }

    [Fact]
    public async Task GetApps_WithNullCallbackUrl_ReturnsEmptyString()
    {
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "a",
            AppName = "A",
            CallbackUrl = null,
            CreatedAt = DateTimeOffset.UtcNow
        };
        _dbContext.AppRegistrations.Add(app);
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await _controller.GetApps(_dbContext, TestJwtOptions);

        var ok = Assert.IsType<OkObjectResult>(result);
        var list = Assert.IsAssignableFrom<IReadOnlyList<AdminAppListItemResponse>>(ok.Value);
        Assert.Equal(string.Empty, list[0].CallbackUrl);
        Assert.Null(list[0].CallbackExpiresAt);
    }

    #endregion

    #region CreateApp

    [Fact]
    public async Task CreateApp_WithEmptyAppName_ReturnsBadRequest()
    {
        SetAdminUser();
        var result = await _controller.CreateApp(
            new AdminCreateAppRequest("", null, 0),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task CreateApp_WithValidName_CreatesApp()
    {
        SetAdminUser();
        _appRegRepoMock.Setup(r => r.AddAsync(It.IsAny<AppRegistrationEntity>())).Returns(Task.CompletedTask).Verifiable();

        var result = await _controller.CreateApp(
            new AdminCreateAppRequest("MyApp", "https://cb.example.com", 3600),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminCreateAppResponse>(ok.Value);
        Assert.Equal("MyApp", response.AppName);
        Assert.Equal("https://cb.example.com", response.CallbackUrl);
        Assert.NotNull(response.CallbackExpiresAt);
        Assert.False(string.IsNullOrEmpty(response.AppId));
        Assert.False(string.IsNullOrEmpty(response.AppSecret));
        _appRegRepoMock.Verify();
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task CreateApp_WithInvalidCallback_DoesNotPersistApp()
    {
        SetAdminUser();

        var result = await _controller.CreateApp(
            new AdminCreateAppRequest(
                "MyApp",
                "https://user:secret@cb.example.com/claims",
                3600),
            _appRegRepoMock.Object,
            CallbackValidator,
            _unitOfWorkMock.Object,
            _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains(
            "Invalid callback URL",
            Assert.IsType<ErrorResponse>(badRequest.Value).Message);
        _appRegRepoMock.Verify(
            repository => repository.AddAsync(It.IsAny<AppRegistrationEntity>()),
            Times.Never);
        _unitOfWorkMock.Verify(
            unit => unit.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task CreateApp_WithNeverExpireTtl_SetsNullExpiry()
    {
        SetAdminUser();
        _appRegRepoMock.Setup(r => r.AddAsync(It.IsAny<AppRegistrationEntity>()))
            .Callback<AppRegistrationEntity, CancellationToken>(
                (app, _) => Assert.Null(app.CallbackExpiresAt))
            .Returns(Task.CompletedTask);

        var result = await _controller.CreateApp(
            new AdminCreateAppRequest("MyApp", "https://cb.example.com", IdentityConstants.CallbackTtlNeverExpire),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminCreateAppResponse>(ok.Value);
        Assert.Null(response.CallbackExpiresAt);
    }

    [Fact]
    public async Task CreateApp_WithEmptyCallbackUrl_SetsNullCallback()
    {
        SetAdminUser();
        _appRegRepoMock.Setup(r => r.AddAsync(It.IsAny<AppRegistrationEntity>()))
            .Callback<AppRegistrationEntity, CancellationToken>((app, _) =>
            {
                Assert.Null(app.CallbackUrl);
                Assert.Null(app.CallbackExpiresAt);
            })
            .Returns(Task.CompletedTask);

        var result = await _controller.CreateApp(
            new AdminCreateAppRequest("MyApp", "", 0),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminCreateAppResponse>(ok.Value);
        Assert.Equal(string.Empty, response.CallbackUrl);
        Assert.Null(response.CallbackExpiresAt);
    }

    [Fact]
    public async Task CreateApp_WithNegativeTtl_UsesDefaultTtl()
    {
        SetAdminUser();
        var before = DateTimeOffset.UtcNow;
        _appRegRepoMock.Setup(r => r.AddAsync(It.IsAny<AppRegistrationEntity>()))
            .Callback<AppRegistrationEntity, CancellationToken>((app, _) =>
            {
                Assert.NotNull(app.CallbackExpiresAt);
                Assert.InRange(app.CallbackExpiresAt!.Value, before.AddSeconds(IdentityConstants.DefaultCallbackTtlSeconds - 5), before.AddSeconds(IdentityConstants.DefaultCallbackTtlSeconds + 5));
            })
            .Returns(Task.CompletedTask);

        var result = await _controller.CreateApp(
            new AdminCreateAppRequest("MyApp", "https://cb.example.com", -10),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task CreateApp_RecordsAnAuditEntryWithoutTheSecret()
    {
        SetAdminUser();
        AppRegistrationEntity? created = null;
        _appRegRepoMock.Setup(r => r.AddAsync(It.IsAny<AppRegistrationEntity>()))
            .Callback<AppRegistrationEntity, CancellationToken>((app, _) => created = app)
            .Returns(Task.CompletedTask);
        var snapshots = CaptureSnapshots();

        var result = await _controller.CreateApp(
            new AdminCreateAppRequest("MyApp", "https://cb.example.com", 3600),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        var response = Assert.IsType<AdminCreateAppResponse>(
            Assert.IsType<OkObjectResult>(result).Value);
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            "app_created", "AppRegistration", response.AppId,
            AdminId, AdminName, "Admin created app: MyApp", It.IsAny<string?>(),
            It.IsAny<string?>(), null, It.IsAny<object?>()), Times.Once);

        // A creation has no before state; the after snapshot carries exactly the fields an operator
        // reads the registration back by.
        var (before, after) = Assert.Single(snapshots);
        Assert.Null(before);
        var afterJson = Serialize(after);
        Assert.Contains("\"appId\":\"" + response.AppId + "\"", afterJson);
        Assert.Contains("\"appName\":\"MyApp\"", afterJson);
        Assert.Contains("\"callbackUrl\":\"https://cb.example.com\"", afterJson);
        Assert.Contains("\"callbackExpiresAt\":", afterJson);
        Assert.Contains("\"isActive\":true", afterJson);

        Assert.NotNull(created);
        AssertNoSecret(afterJson, response.AppSecret, created!.AppSecretHash);
    }

    [Fact]
    public async Task CreateApp_WithEmptyAppName_RecordsNoAudit()
    {
        SetAdminUser();

        await _controller.CreateApp(
            new AdminCreateAppRequest("", null, 0),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        VerifyNoAudit();
    }

    [Fact]
    public async Task CreateApp_WithInvalidCallback_RecordsNoAudit()
    {
        SetAdminUser();

        await _controller.CreateApp(
            new AdminCreateAppRequest("MyApp", "https://user:secret@cb.example.com/claims", 3600),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        VerifyNoAudit();
    }

    #endregion

    #region UpdateCallback

    [Fact]
    public async Task UpdateCallback_WhenAppNotFound_ReturnsNotFound()
    {
        SetAdminUser();
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("missing")).ReturnsAsync((AppRegistrationEntity?)null);

        var result = await _controller.UpdateCallback("missing",
            new AdminUpdateCallbackRequest("https://cb", 3600, true),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task UpdateCallback_WithEmptyCallbackUrl_ClearsCallback()
    {
        SetAdminUser();
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "a",
            AppName = "A",
            CallbackUrl = "https://old",
            CallbackExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            IsActive = false
        };
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("a")).ReturnsAsync(app);

        var result = await _controller.UpdateCallback("a",
            new AdminUpdateCallbackRequest("", 0, true),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.True(Assert.IsType<OperationResponse>(ok.Value).Success);
        Assert.Null(app.CallbackUrl);
        Assert.Null(app.CallbackExpiresAt);
        Assert.True(app.IsActive);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task UpdateCallback_WithCallbackUrl_SetsCallback()
    {
        SetAdminUser();
        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "a", AppName = "A", IsActive = true };
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("a")).ReturnsAsync(app);

        var result = await _controller.UpdateCallback("a",
            new AdminUpdateCallbackRequest("https://new", 7200, false),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal("https://new", app.CallbackUrl);
        Assert.NotNull(app.CallbackExpiresAt);
        Assert.False(app.IsActive);
    }

    [Fact]
    public async Task UpdateCallback_WithInvalidCallback_DoesNotMutateApp()
    {
        SetAdminUser();
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "a",
            AppName = "A",
            CallbackUrl = "https://old.example.com/claims",
            IsActive = true
        };
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("a")).ReturnsAsync(app);

        var result = await _controller.UpdateCallback(
            "a",
            new AdminUpdateCallbackRequest("ftp://cb.example.com/claims", 7200, false),
            _appRegRepoMock.Object,
            CallbackValidator,
            _unitOfWorkMock.Object,
            _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("https://old.example.com/claims", app.CallbackUrl);
        Assert.True(app.IsActive);
        _unitOfWorkMock.Verify(
            unit => unit.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task UpdateCallback_WithNeverExpireTtl_SetsNullExpiry()
    {
        SetAdminUser();
        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "a", AppName = "A" };
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("a")).ReturnsAsync(app);

        var result = await _controller.UpdateCallback("a",
            new AdminUpdateCallbackRequest("https://cb", IdentityConstants.CallbackTtlNeverExpire, true),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        Assert.IsType<OkObjectResult>(result);
        Assert.Null(app.CallbackExpiresAt);
    }

    [Fact]
    public async Task UpdateCallback_RecordsAnAuditEntryShowingTheDeactivation()
    {
        SetAdminUser();
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "a",
            AppName = "MyApp",
            AppSecretHash = "hashed-secret-value",
            CallbackUrl = "https://old.example.com/claims",
            CallbackExpiresAt = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
            IsActive = true
        };
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("a")).ReturnsAsync(app);
        var snapshots = CaptureSnapshots();

        var result = await _controller.UpdateCallback("a",
            new AdminUpdateCallbackRequest("https://new.example.com/claims", 7200, false),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        Assert.IsType<OkObjectResult>(result);
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            "app_callback_updated", "AppRegistration", "a",
            AdminId, AdminName, "Admin updated callback configuration for app: MyApp",
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<object?>()),
            Times.Once);

        // The deactivation has to be readable from the two snapshots alone.
        var (before, after) = Assert.Single(snapshots);
        var beforeJson = Serialize(before);
        var afterJson = Serialize(after);
        Assert.Contains("\"callbackUrl\":\"https://old.example.com/claims\"", beforeJson);
        Assert.Contains("\"callbackExpiresAt\":1700000000", beforeJson);
        Assert.Contains("\"isActive\":true", beforeJson);
        Assert.Contains("\"callbackUrl\":\"https://new.example.com/claims\"", afterJson);
        Assert.Contains("\"callbackExpiresAt\":", afterJson);
        Assert.Contains("\"isActive\":false", afterJson);
        AssertNoSecret(beforeJson + afterJson, "plaintext-app-secret", app.AppSecretHash);
    }

    [Fact]
    public async Task UpdateCallback_WhenAppNotFound_RecordsNoAudit()
    {
        SetAdminUser();
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("missing")).ReturnsAsync((AppRegistrationEntity?)null);

        await _controller.UpdateCallback("missing",
            new AdminUpdateCallbackRequest("https://cb", 3600, true),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        VerifyNoAudit();
    }

    [Fact]
    public async Task UpdateCallback_WithInvalidCallback_RecordsNoAudit()
    {
        SetAdminUser();
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "a",
            AppName = "A",
            CallbackUrl = "https://old.example.com/claims",
            IsActive = true
        };
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("a")).ReturnsAsync(app);

        await _controller.UpdateCallback("a",
            new AdminUpdateCallbackRequest("ftp://cb.example.com/claims", 7200, false),
            _appRegRepoMock.Object, CallbackValidator, _unitOfWorkMock.Object, _auditServiceMock.Object,
            TestContext.Current.CancellationToken);

        VerifyNoAudit();
    }

    /// <summary>
    /// Captures the before/after snapshot arguments handed to <see cref="IAuditService"/> so that a
    /// test can assert on what the audit record would contain.
    /// </summary>
    private List<(object? Before, object? After)> CaptureSnapshots()
    {
        var snapshots = new List<(object? Before, object? After)>();
        _auditServiceMock.Setup(a => a.RecordActionAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<Guid?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<object?>()))
            .Callback<string, string, string, Guid?, string?, string?, string?, string?, object?, object?>(
                (_, _, _, _, _, _, _, _, before, after) => snapshots.Add((before, after)))
            .Returns(Task.CompletedTask);
        return snapshots;
    }

    private void VerifyNoAudit() =>
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<Guid?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<object?>()), Times.Never);

    /// <summary>
    /// Serializes a snapshot exactly the way <c>AuditService</c> does, so the assertions run against
    /// the text that would be persisted.
    /// </summary>
    private static string Serialize(object? snapshot) =>
        snapshot == null
            ? string.Empty
            : System.Text.Json.JsonSerializer.Serialize(
                snapshot,
                new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
                    WriteIndented = false
                });

    private static void AssertNoSecret(string json, string appSecret, string? appSecretHash)
    {
        Assert.DoesNotContain(appSecret, json, StringComparison.Ordinal);
        Assert.DoesNotContain("secret", json, StringComparison.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(appSecretHash))
        {
            Assert.DoesNotContain(appSecretHash, json, StringComparison.Ordinal);
        }
    }

    #endregion

    #region DeleteApp

    [Fact]
    public async Task DeleteApp_WhenAppNotFound_ReturnsNotFound()
    {
        SetAdminUser();
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("missing")).ReturnsAsync((AppRegistrationEntity?)null);

        var result = await _controller.DeleteApp("missing", _appRegRepoMock.Object, _unitOfWorkMock.Object, _auditServiceMock.Object);

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task DeleteApp_WithExistingApp_DeletesAndRecordsAudit()
    {
        SetAdminUser();
        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "a", AppName = "MyApp" };
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("a")).ReturnsAsync(app);
        _appRegRepoMock.Setup(r => r.DeleteAsync(app)).Returns(Task.CompletedTask).Verifiable();

        var result = await _controller.DeleteApp("a", _appRegRepoMock.Object, _unitOfWorkMock.Object, _auditServiceMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.True(Assert.IsType<OperationResponse>(ok.Value).Success);
        _appRegRepoMock.Verify();
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            "app_deleted", "AppRegistration", "a",
            AdminId, AdminName, "Admin deleted app: MyApp", It.IsAny<string?>(),
            It.IsAny<string?>(), null, null), Times.Once);
    }

    #endregion

    #region UpdateSmsPolicy

    private static SmsOptions CreateSmsOptions(params string[] profileKeys)
    {
        var options = new SmsOptions();
        foreach (var key in profileKeys)
        {
            options.Profiles[key] = new SmsProviderProfile { Provider = SmsProviderNames.AlibabaCloud };
        }

        return options;
    }

    [Fact]
    public async Task UpdateSmsPolicy_WithoutProfile_EnablesModeForBypassOnlyDeployment()
    {
        SetAdminUser();
        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "a", AppName = "MyApp" };
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("a")).ReturnsAsync(app);

        var result = await _controller.UpdateSmsPolicy(
            "a", new AdminUpdateSmsPolicyRequest("AutoProvision", null),
            _appRegRepoMock.Object, CreateSmsOptions(), _unitOfWorkMock.Object, _auditServiceMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.True(Assert.IsType<OperationResponse>(ok.Value).Success);
        Assert.Equal(SmsLoginMode.AutoProvision, app.SmsLoginMode);
        Assert.Null(app.SmsProfileKey);
    }

    [Fact]
    public async Task UpdateSmsPolicy_WithUnknownProfile_ReturnsBadRequest()
    {
        SetAdminUser();
        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "a", AppName = "MyApp" };
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("a")).ReturnsAsync(app);

        var result = await _controller.UpdateSmsPolicy(
            "a", new AdminUpdateSmsPolicyRequest("AutoProvision", "typo"),
            _appRegRepoMock.Object, CreateSmsOptions("primary"), _unitOfWorkMock.Object, _auditServiceMock.Object);

        Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(SmsLoginMode.Disabled, app.SmsLoginMode);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task UpdateSmsPolicy_WithConfiguredProfile_StoresProfileKey()
    {
        SetAdminUser();
        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "a", AppName = "MyApp" };
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("a")).ReturnsAsync(app);

        var result = await _controller.UpdateSmsPolicy(
            "a", new AdminUpdateSmsPolicyRequest("ManualApproval", " primary "),
            _appRegRepoMock.Object, CreateSmsOptions("primary"), _unitOfWorkMock.Object, _auditServiceMock.Object);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(SmsLoginMode.ManualApproval, app.SmsLoginMode);
        Assert.Equal("primary", app.SmsProfileKey);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    #endregion

    #region ResetAppSecret

    [Fact]
    public async Task ResetAppSecret_WhenAppNotFound_ReturnsNotFound()
    {
        SetAdminUser();
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("missing")).ReturnsAsync((AppRegistrationEntity?)null);

        var result = await _controller.ResetAppSecret("missing", _appRegRepoMock.Object, _unitOfWorkMock.Object, _auditServiceMock.Object);

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task ResetAppSecret_WithExistingApp_GeneratesNewSecretAndRecordsAudit()
    {
        SetAdminUser();
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "a",
            AppName = "MyApp",
            AppSecretHash = "oldhash",
            CallbackUrl = "https://cb"
        };
        _appRegRepoMock.Setup(r => r.GetByAppIdAsync("a")).ReturnsAsync(app);

        var result = await _controller.ResetAppSecret("a", _appRegRepoMock.Object, _unitOfWorkMock.Object, _auditServiceMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminCreateAppResponse>(ok.Value);
        Assert.False(string.IsNullOrEmpty(response.AppSecret));
        Assert.NotEqual("oldhash", app.AppSecretHash);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            "app_secret_reset", "AppRegistration", "a",
            AdminId, AdminName, "Admin reset app secret: MyApp", It.IsAny<string?>(),
            It.IsAny<string?>(), null, null), Times.Once);
    }

    #endregion

    #region RevokeRefreshToken

    [Fact]
    public async Task RevokeRefreshToken_WithEmptyToken_ReturnsBadRequest()
    {
        SetAdminUser();
        var result = await _controller.RevokeRefreshToken(
            new AdminRevokeRefreshTokenRequest(""),
            _refreshTokenRepoMock.Object, _unitOfWorkMock.Object, _auditServiceMock.Object);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task RevokeRefreshToken_WhenTokenNotFound_ReturnsBadRequest()
    {
        SetAdminUser();
        _refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync(It.IsAny<string>())).ReturnsAsync((RefreshTokenEntity?)null);

        var result = await _controller.RevokeRefreshToken(
            new AdminRevokeRefreshTokenRequest("sometoken"),
            _refreshTokenRepoMock.Object, _unitOfWorkMock.Object, _auditServiceMock.Object);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("not found", Assert.IsType<ErrorResponse>(bad.Value).Message);
    }

    [Fact]
    public async Task RevokeRefreshToken_WithValidToken_RevokesAndRecordsAudit()
    {
        SetAdminUser();
        var accountId = Guid.NewGuid();
        var token = new RefreshTokenEntity { Id = Guid.NewGuid(), AccountId = accountId, TokenValue = "tok", IsRevoked = false };
        _refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("tok")).ReturnsAsync(token);

        var result = await _controller.RevokeRefreshToken(
            new AdminRevokeRefreshTokenRequest("tok"),
            _refreshTokenRepoMock.Object, _unitOfWorkMock.Object, _auditServiceMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.True(Assert.IsType<OperationResponse>(ok.Value).Success);
        Assert.True(token.IsRevoked);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
        _auditServiceMock.Verify(a => a.RecordActionAsync(
            "refresh_token_revoked", "RefreshToken", accountId.ToString(),
            AdminId, AdminName, It.IsAny<string>(), It.IsAny<string?>(),
            It.IsAny<string?>(), null, null), Times.Once);
    }

    [Fact]
    public async Task RevokeRefreshToken_WithWhitespaceToken_TrimsBeforeLookup()
    {
        SetAdminUser();
        _refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("trimmed")).ReturnsAsync((RefreshTokenEntity?)null);

        var result = await _controller.RevokeRefreshToken(
            new AdminRevokeRefreshTokenRequest("  trimmed  "),
            _refreshTokenRepoMock.Object, _unitOfWorkMock.Object, _auditServiceMock.Object);

        Assert.IsType<BadRequestObjectResult>(result);
        _refreshTokenRepoMock.Verify(r => r.GetByTokenValueAsync("trimmed"), Times.Once);
    }

    #endregion

    #region GetUserLoginHistory

    [Fact]
    public async Task GetUserLoginHistory_ReturnsPagedHistory()
    {
        SetAdminUser();
        var userId = Guid.NewGuid();
        var histories = new List<LoginHistoryEntity>
        {
            new()
            {
                Id = Guid.NewGuid(), AccountId = userId, AuthMethod = "Password",
                EventType = "login_success", ClientIp = "1.2.3.4", UserAgent = "ua",
                CreatedAt = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)
            },
            new()
            {
                Id = Guid.NewGuid(), AccountId = userId, AuthMethod = "Sms",
                EventType = "login_failure", FailureReason = "bad code",
                CreatedAt = new DateTimeOffset(2026, 1, 2, 0, 0, 0, TimeSpan.Zero)
            }
        };
        _loginHistoryRepoMock.Setup(r => r.GetByAccountIdAsync(userId, 20, 0)).ReturnsAsync(histories);

        var result = await _controller.GetUserLoginHistory(userId, null, null, _loginHistoryRepoMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<AdminLoginHistoryItemResponse>>(ok.Value);
        Assert.Equal(2, response.Items.Count);
        Assert.Equal("Password", response.Items[0].AuthMethod);
        Assert.Equal("login_success", response.Items[0].EventType);
        Assert.Equal("1.2.3.4", response.Items[0].ClientIp);
        Assert.Equal("ua", response.Items[0].UserAgent);
        Assert.Null(response.Items[0].FailureReason);
        Assert.Equal("bad code", response.Items[1].FailureReason);
    }

    [Fact]
    public async Task GetUserLoginHistory_TotalComesFromRepositoryCount_NotPageSize()
    {
        SetAdminUser();
        var userId = Guid.NewGuid();
        _loginHistoryRepoMock.Setup(r => r.CountByAccountIdAsync(userId)).ReturnsAsync(137);
        _loginHistoryRepoMock.Setup(r => r.GetByAccountIdAsync(userId, 20, 0))
            .ReturnsAsync(new List<LoginHistoryEntity>
            {
                new() { Id = Guid.NewGuid(), AccountId = userId, AuthMethod = "Password", EventType = "login_success" }
            });

        var result = await _controller.GetUserLoginHistory(userId, null, null, _loginHistoryRepoMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<AdminLoginHistoryItemResponse>>(ok.Value);
        // 回归防护：这里曾经返回 items.Count（当前页条数），前端据此算出的总页数永远是 1。
        Assert.Equal(137, response.Total);
        Assert.Single(response.Items);
    }

    [Fact]
    public async Task GetUserLoginHistory_WithCustomPaging_PassesCorrectSkip()
    {
        SetAdminUser();
        var userId = Guid.NewGuid();
        _loginHistoryRepoMock.Setup(r => r.GetByAccountIdAsync(userId, 10, 20)).ReturnsAsync(new List<LoginHistoryEntity>());

        var result = await _controller.GetUserLoginHistory(userId, 3, 10, _loginHistoryRepoMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<AdminLoginHistoryItemResponse>>(ok.Value);
        Assert.Equal(3, response.Page);
        Assert.Equal(10, response.PageSize);
    }

    [Fact]
    public async Task GetUserLoginHistory_WithInvalidPage_DefaultsToOne()
    {
        SetAdminUser();
        var userId = Guid.NewGuid();
        _loginHistoryRepoMock.Setup(r => r.GetByAccountIdAsync(userId, 20, 0)).ReturnsAsync(new List<LoginHistoryEntity>());

        var result = await _controller.GetUserLoginHistory(userId, 0, 20, _loginHistoryRepoMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<AdminLoginHistoryItemResponse>>(ok.Value);
        Assert.Equal(1, response.Page);
    }

    [Fact]
    public async Task GetUserLoginHistory_PageSizeCappedAt100()
    {
        SetAdminUser();
        var userId = Guid.NewGuid();
        _loginHistoryRepoMock.Setup(r => r.GetByAccountIdAsync(userId, 100, 0)).ReturnsAsync(new List<LoginHistoryEntity>());

        var result = await _controller.GetUserLoginHistory(userId, 1, 500, _loginHistoryRepoMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<AdminLoginHistoryItemResponse>>(ok.Value);
        Assert.Equal(100, response.PageSize);
    }

    #endregion

    #region GetAuditLogs

    [Fact]
    public async Task GetAuditLogs_ReturnsPagedLogs()
    {
        SetAdminUser();
        var logs = new List<AuditLogEntity>
        {
            new()
            {
                Id = Guid.NewGuid(), Action = "account_created", TargetType = "Account",
                TargetId = "abc", ActorId = AdminId, ActorName = AdminName,
                Description = "Created", ClientIp = "1.2.3.4", CorrelationId = "corr",
                CreatedAt = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)
            }
        };
        _auditLogRepoMock.Setup(r => r.QueryAsync(null, null, null, null, 20, 0)).ReturnsAsync(logs);

        var result = await _controller.GetAuditLogs(null, null, null, null, null, null, _auditLogRepoMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<AdminAuditLogItemResponse>>(ok.Value);
        Assert.Single(response.Items);
        Assert.Equal("account_created", response.Items[0].Action);
        Assert.Equal("Account", response.Items[0].TargetType);
        Assert.Equal("abc", response.Items[0].TargetId);
        Assert.Equal(AdminId.ToString(), response.Items[0].ActorId);
        Assert.Equal(AdminName, response.Items[0].ActorName);
        Assert.Equal("1.2.3.4", response.Items[0].ClientIp);
        Assert.Equal("corr", response.Items[0].CorrelationId);
    }

    [Fact]
    public async Task GetAuditLogs_TotalComesFromRepositoryCount_NotPageSize()
    {
        SetAdminUser();
        _auditLogRepoMock.Setup(r => r.CountAsync(null, null, null, null)).ReturnsAsync(84);
        _auditLogRepoMock.Setup(r => r.QueryAsync(null, null, null, null, 20, 0))
            .ReturnsAsync(new List<AuditLogEntity>
            {
                new() { Id = Guid.NewGuid(), Action = "account_created", TargetType = "Account", TargetId = "abc" }
            });

        var result = await _controller.GetAuditLogs(null, null, null, null, null, null, _auditLogRepoMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<AdminAuditLogItemResponse>>(ok.Value);
        // 回归防护：同上，Total 必须是过滤后的总条数，不是当前页条数。
        Assert.Equal(84, response.Total);
        Assert.Single(response.Items);
    }

    [Fact]
    public async Task GetAuditLogs_CountReceivesSameFiltersAsQuery()
    {
        SetAdminUser();
        var actorId = Guid.NewGuid();
        _auditLogRepoMock.Setup(r => r.CountAsync("login", "Session", "target1", actorId)).ReturnsAsync(3);
        _auditLogRepoMock.Setup(r => r.QueryAsync("login", "Session", "target1", actorId, 10, 10))
            .ReturnsAsync(new List<AuditLogEntity>());

        await _controller.GetAuditLogs("login", "Session", "target1", actorId, 2, 10, _auditLogRepoMock.Object);

        _auditLogRepoMock.Verify(r => r.CountAsync("login", "Session", "target1", actorId), Times.Once);
    }

    [Fact]
    public async Task GetAuditLogs_WithFilters_PassesFiltersToRepository()
    {
        SetAdminUser();
        var actorId = Guid.NewGuid();
        _auditLogRepoMock.Setup(r => r.QueryAsync("login", "Session", "target1", actorId, 10, 10))
            .ReturnsAsync(new List<AuditLogEntity>());

        var result = await _controller.GetAuditLogs("login", "Session", "target1", actorId, 2, 10, _auditLogRepoMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<AdminAuditLogItemResponse>>(ok.Value);
        Assert.Equal(2, response.Page);
        Assert.Equal(10, response.PageSize);
        _auditLogRepoMock.Verify(r => r.QueryAsync("login", "Session", "target1", actorId, 10, 10), Times.Once);
    }

    [Fact]
    public async Task GetAuditLogs_WithInvalidPaging_DefaultsToValidValues()
    {
        SetAdminUser();
        _auditLogRepoMock.Setup(r => r.QueryAsync(null, null, null, null, It.IsAny<int>(), It.IsAny<int>()))
            .ReturnsAsync(new List<AuditLogEntity>());

        var result = await _controller.GetAuditLogs(null, null, null, null, -1, 0, _auditLogRepoMock.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<PagedResponse<AdminAuditLogItemResponse>>(ok.Value);
        Assert.Equal(1, response.Page);
        // pageSize<1 视为未指定，回落到默认 20（与 /api/admin/users、/api/gateway/users/search 一致）。
        // 改统一走 PageRequest.Normalize 之前，这里曾经因为写法不同而返回 1。
        Assert.Equal(PageRequest.DefaultPageSize, response.PageSize);
    }

    #endregion
}
