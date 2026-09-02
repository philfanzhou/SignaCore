namespace SignaCore.Host.Models;

// Requests and responses used only by the admin console (/api/admin/*). See ApiModels.cs for
// common responses shared by all three API surfaces.

public sealed record AdminLoginRequest(string Username, string Password, bool RememberMe);

public sealed record AdminSessionResponse(
    string AccountId,
    string Username,
    bool IsAuthenticated);

public sealed record AdminCreateUserRequest(string Username, string Password, string? DisplayName, string? Remark, string? Nickname);

public sealed record AdminCreatePhoneUserRequest(string Phone, string? DisplayName, string? Remark, string? Nickname);

public sealed record AdminCreateUserResponse(
    string UserId,
    string Username,
    string DisplayName,
    bool IsActive,
    string Remark,
    string? Nickname,
    long CreatedAt);

public sealed record AdminUpdateRemarkRequest(string? Remark);

public sealed record AdminUpdateNicknameRequest(string? Nickname);

public sealed record AdminUpdateStatusRequest(bool IsActive);

/// <summary>
/// One row of the application list. The interactive OIDC members are appended after the existing
/// ones: a console built against the earlier shape keeps reading the same names in the same order,
/// and an application that predates interactive configuration reports the fail-closed defaults
/// rather than nothing.
/// <para>
/// <c>CallbackUrl</c> is the server-to-server claims callback and has nothing to do with
/// <c>RedirectUris</c>. They are separate registrations with separate validation, and no value is
/// ever copied between them.
/// </para>
/// </summary>
public sealed record AdminAppListItemResponse(
    string AppId,
    string AppName,
    string CallbackUrl,
    long? CallbackExpiresAt,
    bool IsActive,
    long CreatedAt,
    string LdapLoginMode,
    string SmsLoginMode,
    string? SmsProfileKey,
    string WechatLoginMode,
    string AudienceMode,
    string Audience,
    string ClientType,
    bool AllowAuthorizationCode,
    IReadOnlyList<string> AllowedScopes,
    bool AllowRefreshToken,
    int? IdentitySessionMaxAgeSeconds,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris);

/// <summary>One registered browser URI. The id is stable across unrelated policy edits.</summary>
public sealed record AdminAppRedirectUriResponse(Guid Id, string Kind, string Uri);

/// <summary>
/// The interactive OIDC configuration of one application, with the two URI sets kept apart by kind.
/// </summary>
public sealed record AdminAppOidcResponse(
    string AppId,
    string ClientType,
    bool AllowAuthorizationCode,
    IReadOnlyList<string> AllowedScopes,
    bool AllowRefreshToken,
    int? IdentitySessionMaxAgeSeconds,
    string AudienceMode,
    IReadOnlyList<AdminAppRedirectUriResponse> RedirectUris,
    IReadOnlyList<AdminAppRedirectUriResponse> PostLogoutRedirectUris);

/// <summary>
/// A complete replacement of the interactive policy fields. The audience mode is deliberately
/// absent: it has its own endpoint, and enabling the code flow without a per-application audience
/// is a rejection rather than an implicit audience change.
/// </summary>
public sealed record AdminUpdateOidcPolicyRequest(
    string? ClientType,
    bool AllowAuthorizationCode,
    IReadOnlyList<string>? AllowedScopes,
    bool AllowRefreshToken,
    int? IdentitySessionMaxAgeSeconds);

/// <summary>Adds URIs to one kind. Either every value is registered or none is.</summary>
public sealed record AdminAddRedirectUrisRequest(string Kind, IReadOnlyList<string>? Uris);

public sealed record AdminCreateAppRequest(string AppName, string? CallbackUrl, int TtlSeconds);

public sealed record AdminCreateAppResponse(
    string AppId,
    string AppSecret,
    string AppName,
    string CallbackUrl,
    long? CallbackExpiresAt);

public sealed record AdminUpdateCallbackRequest(string? CallbackUrl, int TtlSeconds, bool IsActive);

public sealed record AdminUpdateLdapPolicyRequest(string Mode);

public sealed record AdminUpdateSmsPolicyRequest(string Mode, string? ProfileKey);

public sealed record AdminAddSmsUserRequest(string Phone);

public sealed record AdminSmsUserResponse(
    string LoginId,
    string UserId,
    string Phone,
    string ApprovalSource,
    bool IsActive,
    long CreatedAt);

public sealed record AdminUpdateWechatPolicyRequest(string Mode);

public sealed record AdminUpdateAudienceModeRequest(string Mode);

public sealed record AdminAddExchangeTrustRequest(string SourceAppId);

/// <summary>
/// One directed exchange trust: this application accepts refresh tokens issued to
/// <paramref name="SourceAppId"/>.
/// </summary>
public sealed record AdminExchangeTrustResponse(
    string SourceAppId,
    string SourceAppName,
    bool SourceIsActive,
    long CreatedAt);

/// <summary><paramref name="OpenId"/> is masked: the raw OpenId is never returned by the admin API.</summary>
public sealed record AdminWechatUserResponse(
    string LoginId,
    string UserId,
    string OpenId,
    string ApprovalSource,
    bool IsActive,
    long CreatedAt);

public sealed record AdminAddLdapUserRequest(string DirectoryKey, string Username);

public sealed record AdminLdapUserResponse(
    string CredentialId,
    string UserId,
    string Username,
    string SamAccountName,
    string DirectoryKey,
    string ApprovalSource,
    bool IsActive,
    long CreatedAt);

public sealed record AdminRevokeRefreshTokenRequest(string RefreshToken);

public sealed record AdminLoginHistoryItemResponse(
    string AuthMethod,
    string EventType,
    string ClientIp,
    string UserAgent,
    string? FailureReason,
    string? AppId,
    long CreatedAt);

public sealed record AdminAuditLogItemResponse(
    string Action,
    string TargetType,
    string TargetId,
    string? ActorId,
    string? ActorName,
    string? Description,
    string? ClientIp,
    string? CorrelationId,
    long CreatedAt);
