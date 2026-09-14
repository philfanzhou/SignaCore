using Microsoft.AspNetCore.Authentication;
using ServiceMantle.Audit;
using ServiceMantle.Management;
using SignaCore.Database;
using SignaCore.Domain;
using SignaCore.Domain.Validators;
using SignaCore.Host.Http;
using SignaCore.Host.Services;

namespace SignaCore.Host.Management;

/// <summary>
/// Adapts SignaCore's administrator authentication to the ServiceMantle management identity SPI
/// for the shared management session.
/// </summary>
/// <remarks>
/// The provider reuses exactly the legacy admin login checks: the shared password validator, the
/// bootstrap-administrator restriction, and the login-attempt/audit commit path. It reads the
/// credentials from the scoped <see cref="ManagementCredentialAccessor"/>; no credential travels
/// through this interface or appears in any result. Outcomes map onto the closed
/// <see cref="ManagementIdentityResult"/> set: an invalid password or a non-bootstrap account is
/// an expected rejection (<c>Unauthenticated</c>), never a provider failure.
/// </remarks>
internal sealed class SignaCoreManagementIdentityProvider(
    ManagementCredentialAccessor credentials,
    ValidatorFactory validatorFactory,
    AdminIdentityOptions adminIdentity,
    AdminLoginStateRecorder loginStateRecorder,
    IHttpContextAccessor httpContextAccessor,
    ILogger<SignaCoreManagementIdentityProvider> logger) : IManagementIdentityProvider
{
    public async ValueTask<ManagementIdentityResult> GetIdentityAsync(
        CancellationToken cancellationToken = default)
    {
        if (!credentials.HasCredentials)
        {
            return ManagementIdentityResult.Unauthenticated();
        }

        var username = credentials.Username;

        var validator = validatorFactory.GetValidator(IdentityConstants.GrantTypePassword);
        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypePassword,
            Username = username,
            Password = credentials.Password,
            CancellationToken = cancellationToken
        });

        if (!result.IsSuccess)
        {
            await CommitAsync(result, null, username, "login_failure", result.ErrorMessage, cancellationToken);
            return ManagementIdentityResult.Unauthenticated();
        }

        var displayName = result.DisplayName ?? username;
        var configuredAdmin = adminIdentity.Username.Trim();
        if (string.IsNullOrWhiteSpace(configuredAdmin)
            || !string.Equals(displayName, configuredAdmin, StringComparison.OrdinalIgnoreCase))
        {
            await CommitAsync(
                result, result.Account.Id, displayName, "login_failure", "bootstrap_admin_required", cancellationToken);
            return ManagementIdentityResult.Unauthenticated();
        }

        await CommitAsync(result, result.Account.Id, displayName, "login_success", null, cancellationToken);

        logger.LogInformation(
            "Management session login succeeded for the bootstrap administrator: AccountId={AccountId}",
            result.Account.Id);

        return ManagementIdentityResult.Authenticated(ManagementIdentity.Create(
            WellKnownManagementAuditOperatorSources.InteractiveAdmin,
            result.Account.Id.ToString(),
            [ManagementPermission.Admin],
            displayName));
    }

    private async Task CommitAsync(
        ValidationResult result,
        Guid? accountId,
        string username,
        string eventType,
        string? failureReason,
        CancellationToken cancellationToken)
    {
        var httpContext = httpContextAccessor.HttpContext;
        await loginStateRecorder.CommitAsync(
            result,
            accountId,
            username,
            eventType,
            failureReason,
            httpContext?.GetClientIp(),
            httpContext?.Request.Headers.UserAgent,
            cancellationToken);
    }
}
