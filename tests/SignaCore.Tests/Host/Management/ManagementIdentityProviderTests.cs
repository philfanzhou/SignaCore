using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ServiceMantle.Audit;
using ServiceMantle.Health;
using ServiceMantle.Management;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using SignaCore.Host.Installation;
using SignaCore.Host.Management;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Management;

public sealed class SignaCoreManagementIdentityProviderTests : IAsyncDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private IdentityDbContext _context = null!;
    private readonly ManagementCredentialAccessor _credentials = new();
    private readonly Guid _adminId = Guid.NewGuid();
    private const string AdminName = "session_admin";
    private const string AdminPassword = "SessionAdmin123!";

    public SignaCoreManagementIdentityProviderTests()
    {
    }

    private async Task EnsureContextAsync()
    {
        if (_context is not null)
        {
            return;
        }

        await _connection.OpenAsync(TestContext.Current.CancellationToken);
        _context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(_connection).Options);
        await _context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
    }

    private async Task<SignaCoreManagementIdentityProvider> CreateProviderAsync(string adminUsername = AdminName)
    {
        await EnsureContextAsync();

        var hasher = new BCryptPasswordHasher(new PasswordHasherOptions());
        _context.Accounts.Add(new AccountEntity { Id = _adminId, IsActive = true });
        _context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = _adminId,
            Username = AdminName,
            PasswordHash = hasher.HashPassword(AdminPassword)
        });
        await _context.SaveChangesAsync(TestContext.Current.CancellationToken);

        var validator = new PasswordValidator(
            new PasswordCredentialRepository(_context),
            new AccountRepository(_context),
            new LoginAttemptRepository(_context),
            hasher,
            NullLogger<PasswordValidator>.Instance);

        var accessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext() };

        return new SignaCoreManagementIdentityProvider(
            _credentials,
            new ValidatorFactory([validator], NullLogger<ValidatorFactory>.Instance),
            new AdminIdentityOptions { Username = adminUsername },
            new AdminLoginStateRecorder(
                new LoginAttemptRepository(_context),
                new AuditService(new LoginHistoryRepository(_context), new AuditLogRepository(_context)),
                new EfCoreUnitOfWork(_context),
                _context,
                NullLogger<AdminLoginStateRecorder>.Instance),
            accessor,
            NullLogger<SignaCoreManagementIdentityProvider>.Instance);
    }

    [Fact]
    public async Task GetIdentity_WithoutCredentials_IsUnauthenticatedWithoutValidation()
    {
        var provider = await CreateProviderAsync();

        var result = await provider.GetIdentityAsync(TestContext.Current.CancellationToken);

        Assert.Equal(ManagementIdentityStatus.Unauthenticated, result.Status);
        Assert.Null(result.Identity);
        Assert.Empty(await _context.LoginHistories.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetIdentity_WithWrongPassword_IsUnauthenticatedAndRecordsFailure()
    {
        var provider = await CreateProviderAsync();
        _credentials.Set(AdminName, "wrong-password-value");

        var result = await provider.GetIdentityAsync(TestContext.Current.CancellationToken);

        Assert.Equal(ManagementIdentityStatus.Unauthenticated, result.Status);
        _context.ChangeTracker.Clear();
        var history = Assert.Single(await _context.LoginHistories.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("login_failure", history.EventType);
        Assert.Equal("admin_login", history.AuthMethod);
        Assert.NotNull(history.FailureReason);
        Assert.Single(await _context.LoginAttempts.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetIdentity_WithNonBootstrapAccount_IsUnauthenticatedWithBootstrapReason()
    {
        await EnsureContextAsync();
        // A second, valid password account that is not the configured bootstrap administrator.
        var otherId = Guid.NewGuid();
        var hasher = new BCryptPasswordHasher(new PasswordHasherOptions());
        _context.Accounts.Add(new AccountEntity { Id = otherId, IsActive = true });
        _context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = otherId,
            Username = "other-operator",
            PasswordHash = hasher.HashPassword("OtherOperator123!")
        });
        await _context.SaveChangesAsync(TestContext.Current.CancellationToken);

        var provider = await CreateProviderAsync();
        _credentials.Set("other-operator", "OtherOperator123!");

        var result = await provider.GetIdentityAsync(TestContext.Current.CancellationToken);

        Assert.Equal(ManagementIdentityStatus.Unauthenticated, result.Status);
        _context.ChangeTracker.Clear();
        var history = Assert.Single(await _context.LoginHistories.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("bootstrap_admin_required", history.FailureReason);
        Assert.Equal(otherId, history.AccountId);
    }

    [Fact]
    public async Task GetIdentity_WithBootstrapAdmin_IsAuthenticatedWithAdminPermission()
    {
        var provider = await CreateProviderAsync();
        _credentials.Set(AdminName, AdminPassword);

        var result = await provider.GetIdentityAsync(TestContext.Current.CancellationToken);

        Assert.Equal(ManagementIdentityStatus.Authenticated, result.Status);
        var identity = result.Identity!;
        Assert.Equal(_adminId.ToString(), identity.OperatorId);
        Assert.Equal(WellKnownManagementAuditOperatorSources.InteractiveAdmin, identity.Source);
        Assert.Equal(AdminName, identity.DisplayName);
        var permission = Assert.Single(identity.Permissions);
        Assert.Equal(ManagementPermission.Admin, permission);

        _context.ChangeTracker.Clear();
        var history = Assert.Single(await _context.LoginHistories.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("login_success", history.EventType);
        Assert.Null(history.FailureReason);
    }

    [Fact]
    public async Task GetIdentity_PasswordsNeverAppearInResults()
    {
        var provider = await CreateProviderAsync();
        _credentials.Set(AdminName, AdminPassword);

        var result = await provider.GetIdentityAsync(TestContext.Current.CancellationToken);

        Assert.DoesNotContain(AdminPassword, result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(AdminPassword, result.Identity?.ToString() ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invoker_ConvertsProviderExceptionsToClosedFailure()
    {
        var throwing = new ThrowingProvider();
        var result = await ManagementIdentityProviderInvoker.InvokeAsync(
            throwing, TestContext.Current.CancellationToken);
        Assert.Equal(ManagementIdentityStatus.Failed, result.Status);
        Assert.Equal("management_identity.provider_failed", result.ErrorCode);

        var cancelling = new CancellingProvider();
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => cancelling.GetIdentityAsync(cancellation.Token).AsTask());
        Assert.Equal(cancellation.Token, exception.CancellationToken);
    }

    private sealed class ThrowingProvider : IManagementIdentityProvider
    {
        public ValueTask<ManagementIdentityResult> GetIdentityAsync(
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("upstream identity failure");
    }

    private sealed class CancellingProvider : IManagementIdentityProvider
    {
        public ValueTask<ManagementIdentityResult> GetIdentityAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromCanceled<ManagementIdentityResult>(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (_context is not null)
        {
            await _context.DisposeAsync();
        }

        await _connection.DisposeAsync();
    }
}

public sealed class ManagementLoginAdapterTests
{
    private static HttpContext CreateHttpContext(IServiceProvider services, string body)
    {
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Body = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(body));
        return context;
    }

    private static ServiceProvider CreateServices(IManagementIdentityProvider provider)
    {
        var services = new ServiceCollection();
        services.AddScoped<ManagementCredentialAccessor>();
        services.AddSingleton(provider);
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task MalformedBody_IsAnExpectedRejection()
    {
        var recorder = new RecordingProvider();
        using var services = (ServiceProvider)CreateServices(recorder);
        var context = CreateHttpContext(services, "not json at all");

        var result = await ManagementSessionComposition.LoginAdapter(
            context, TestContext.Current.CancellationToken);

        Assert.Equal(ManagementIdentityStatus.Unauthenticated, result.Status);
        Assert.Equal(0, recorder.Calls);
    }

    [Theory]
    [InlineData("{\"username\": \"  \", \"password\": \"x\"}")]
    [InlineData("{\"username\": \"admin\"}")]
    [InlineData("{}")]
    [InlineData("null")]
    public async Task BodyWithoutUsableCredentials_IsAnExpectedRejection(string body)
    {
        var recorder = new RecordingProvider();
        using var services = (ServiceProvider)CreateServices(recorder);
        var context = CreateHttpContext(services, body);

        var result = await ManagementSessionComposition.LoginAdapter(
            context, TestContext.Current.CancellationToken);

        Assert.Equal(ManagementIdentityStatus.Unauthenticated, result.Status);
        Assert.Equal(0, recorder.Calls);
    }

    [Fact]
    public async Task ValidBody_PlacesCredentialsAndInvokesProvider()
    {
        var recorder = new RecordingProvider();
        using var services = (ServiceProvider)CreateServices(recorder);
        var context = CreateHttpContext(services,
            "{\"Username\": \"  SessionAdmin  \", \"password\": \"SessionAdmin123!\"}");

        var result = await ManagementSessionComposition.LoginAdapter(
            context, TestContext.Current.CancellationToken);

        Assert.Equal(ManagementIdentityStatus.Authenticated, result.Status);
        Assert.Equal(1, recorder.Calls);
        var accessor = context.RequestServices.GetRequiredService<ManagementCredentialAccessor>();
        Assert.True(accessor.HasCredentials);
        Assert.Equal("SessionAdmin", accessor.Username);
    }

    [Fact]
    public async Task PreCancelledToken_PropagatesCleanly()
    {
        var recorder = new RecordingProvider();
        using var services = (ServiceProvider)CreateServices(recorder);
        var context = CreateHttpContext(services, "{\"username\": \"a\", \"password\": \"b\"}");
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ManagementSessionComposition.LoginAdapter(context, cancellation.Token).AsTask());
        Assert.Equal(cancellation.Token, exception.CancellationToken);
    }

    private sealed class RecordingProvider : IManagementIdentityProvider
    {
        public int Calls { get; private set; }

        public ValueTask<ManagementIdentityResult> GetIdentityAsync(
            CancellationToken cancellationToken = default)
        {
            Calls++;
            return ValueTask.FromResult(ManagementIdentityResult.Authenticated(
                ManagementIdentity.Create(
                    WellKnownManagementAuditOperatorSources.InteractiveAdmin,
                    "operator-1",
                    [ManagementPermission.Admin])));
        }
    }
}
