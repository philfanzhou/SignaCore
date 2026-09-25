using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database.Entity;

namespace SignaCore.Database;

public class IdentityDbContext : DbContext, IServiceDbContext
{
    private static readonly ValueConverter<DateTimeOffset, long> UnixMicrosecondsConverter = new(
        value => (value.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10,
        value => DateTimeOffset.UnixEpoch.AddTicks(value * 10));

    public IdentityDbContext(DbContextOptions<IdentityDbContext> options) : base(options)
    {
    }

    public DbSet<AccountEntity> Accounts => Set<AccountEntity>();
    public DbSet<PasswordCredentialEntity> PasswordCredentials => Set<PasswordCredentialEntity>();
    public DbSet<UserLoginEntity> UserLogins => Set<UserLoginEntity>();
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    public DbSet<AppRegistrationEntity> AppRegistrations => Set<AppRegistrationEntity>();
    public DbSet<AppRedirectUriEntity> AppRedirectUris => Set<AppRedirectUriEntity>();
    public DbSet<SecurityKeyEntity> SecurityKeys => Set<SecurityKeyEntity>();
    public DbSet<OtpEntity> Otps => Set<OtpEntity>();
    public DbSet<LoginAttemptEntity> LoginAttempts => Set<LoginAttemptEntity>();
    public DbSet<LoginHistoryEntity> LoginHistories => Set<LoginHistoryEntity>();
    public DbSet<LdapCredentialEntity> LdapCredentials => Set<LdapCredentialEntity>();
    public DbSet<AppLdapAccessEntity> AppLdapAccesses => Set<AppLdapAccessEntity>();
    public DbSet<AppSmsAccessEntity> AppSmsAccesses => Set<AppSmsAccessEntity>();
    public DbSet<AppWechatAccessEntity> AppWechatAccesses => Set<AppWechatAccessEntity>();
    public DbSet<AppExchangeTrustEntity> AppExchangeTrusts => Set<AppExchangeTrustEntity>();
    public DbSet<AuthorizationRequestEntity> AuthorizationRequests => Set<AuthorizationRequestEntity>();
    public DbSet<IdentitySessionEntity> IdentitySessions => Set<IdentitySessionEntity>();
    public DbSet<AuthorizationCodeEntity> AuthorizationCodes => Set<AuthorizationCodeEntity>();
    public DbSet<LogoutRequestEntity> LogoutRequests => Set<LogoutRequestEntity>();
    public DbSet<OidcRateLimitBucketEntity> OidcRateLimitBuckets => Set<OidcRateLimitBucketEntity>();
    public DbSet<ManagementBearerSessionEntity> ManagementBearerSessions => Set<ManagementBearerSessionEntity>();

    // ServiceMantle shared installation state (service_installations): the runtime authority for
    // installation status and the one-time setup code. The consumer owns this mapping, its
    // migrations, and every save/transaction boundary.
    public DbSet<ServiceInstallationEntity> ServiceInstallations => Set<ServiceInstallationEntity>();

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        ApplyNormalizedValues();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(
        bool acceptAllChangesOnSuccess,
        CancellationToken cancellationToken = default)
    {
        ApplyNormalizedValues();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AccountEntity>(entity =>
        {
            entity.ToTable("accounts");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.IsActive).HasColumnName("is_active");
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.Property(e => e.Remark).HasColumnName("remark").HasMaxLength(IdentityConstants.MaxRemarkLength);
            entity.Property(e => e.RemarkNormalized).HasColumnName("remark_normalized").HasMaxLength(IdentityConstants.MaxRemarkLength);
            entity.Property(e => e.Nickname).HasColumnName("nickname").HasMaxLength(IdentityConstants.MaxNicknameLength);
            entity.Property(e => e.NicknameNormalized).HasColumnName("nickname_normalized").HasMaxLength(IdentityConstants.MaxNicknameLength);
            ConfigureInstant(entity.Property(e => e.LastLoginAt).HasColumnName("last_login_at"));
            entity.Property(e => e.LastLoginIp).HasColumnName("last_login_ip").HasMaxLength(IdentityConstants.MaxClientIpLength);
            entity.Property(e => e.LastLoginMethod).HasColumnName("last_login_method").HasMaxLength(IdentityConstants.MaxAuthMethodLength);
            entity.Property(e => e.TotalLoginCount).HasColumnName("total_login_count");
        });

        modelBuilder.Entity<ManagementBearerSessionEntity>(entity =>
        {
            entity.ToTable("management_bearer_sessions", table =>
            {
                table.HasCheckConstraint("CK_management_bearer_sessions_digest_length", "length(token_digest) = 71");
                table.HasCheckConstraint("CK_management_bearer_sessions_expiry", "expires_at > created_at");
                table.HasCheckConstraint("CK_management_bearer_sessions_revocation", "revoked_at IS NULL OR revoked_at >= created_at");
            });
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.TokenDigest).HasColumnName("token_digest").HasMaxLength(71).IsRequired();
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            ConfigureInstant(entity.Property(e => e.ExpiresAt).HasColumnName("expires_at"));
            ConfigureInstant(entity.Property(e => e.RevokedAt).HasColumnName("revoked_at"));
            entity.HasIndex(e => e.TokenDigest).IsUnique();
            entity.HasIndex(e => e.ExpiresAt);
            entity.HasOne<AccountEntity>().WithMany().HasForeignKey(e => e.AccountId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<PasswordCredentialEntity>(entity =>
        {
            entity.ToTable("password_credentials");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            entity.Property(e => e.Username).HasColumnName("username").HasMaxLength(IdentityConstants.MaxUsernameLength);
            entity.Property(e => e.UsernameNormalized).HasColumnName("username_normalized").HasMaxLength(IdentityConstants.MaxUsernameLength);
            entity.Property(e => e.PasswordHash).HasColumnName("password_hash").HasMaxLength(IdentityConstants.MaxPasswordHashLength);
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.HasIndex(e => e.UsernameNormalized).IsUnique();
            entity.HasIndex(e => e.AccountId);
        });

        modelBuilder.Entity<UserLoginEntity>(entity =>
        {
            entity.ToTable("user_logins");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            entity.Property(e => e.ProviderName).HasColumnName("provider_name").HasMaxLength(IdentityConstants.MaxProviderNameLength);
            entity.Property(e => e.ProviderNameNormalized).HasColumnName("provider_name_normalized").HasMaxLength(IdentityConstants.MaxProviderNameLength);
            entity.Property(e => e.ProviderUserId).HasColumnName("provider_user_id").HasMaxLength(IdentityConstants.MaxProviderUserIdLength);
            entity.HasIndex(e => new { e.ProviderNameNormalized, e.ProviderUserId }).IsUnique();
            entity.HasIndex(e => e.AccountId);
        });

        modelBuilder.Entity<RefreshTokenEntity>(entity =>
        {
            entity.ToTable(
                "refresh_tokens",
                table =>
                {
                    table.HasCheckConstraint(
                        "CK_refresh_tokens_app_id_not_empty",
                        "app_id <> ''");
                    // PS-07/PS-06: a row is either a complete legacy row (every interactive
                    // marker null, so only a legacy row can carry parent/consumed) or a complete
                    // interactive row (session, scope, and auth time all present). A partial
                    // marker is rejected on both providers.
                    table.HasCheckConstraint(
                        "CK_refresh_tokens_family_marker",
                        "(identity_session_id IS NULL AND scope IS NULL AND auth_time IS NULL "
                        + "AND consumed_at IS NULL AND parent_id IS NULL) "
                        + "OR (identity_session_id IS NOT NULL AND scope IS NOT NULL "
                        + "AND auth_time IS NOT NULL)");
                    // PS-06: a root names itself and has no parent; a child names another row as
                    // both its root and its immediate parent, and is never its own parent.
                    table.HasCheckConstraint(
                        "CK_refresh_tokens_family_shape",
                        "(family_id = id AND parent_id IS NULL) "
                        + "OR (family_id <> id AND parent_id IS NOT NULL AND parent_id <> id)");
                });
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            entity.Property(e => e.TokenValue).HasColumnName("token_value").HasMaxLength(IdentityConstants.MaxRefreshTokenLength);
            ConfigureInstant(entity.Property(e => e.ExpiresAt).HasColumnName("expires_at"));
            entity.Property(e => e.IsRevoked).HasColumnName("is_revoked");
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.Property(e => e.AppId).HasColumnName("app_id").HasMaxLength(IdentityConstants.MaxAppIdLength).IsRequired();
            entity.Property(e => e.LdapCredentialId).HasColumnName("ldap_credential_id");
            entity.Property(e => e.SmsUserLoginId).HasColumnName("sms_user_login_id");
            entity.Property(e => e.WechatUserLoginId).HasColumnName("wechat_user_login_id");
            entity.Property(e => e.SourceAppId).HasColumnName("source_app_id").HasMaxLength(IdentityConstants.MaxAppIdLength);
            entity.Property(e => e.FamilyId).HasColumnName("family_id");
            entity.Property(e => e.ParentId).HasColumnName("parent_id");
            entity.Property(e => e.IdentitySessionId).HasColumnName("identity_session_id");
            // The family scope copies the authorization-code snapshot byte for byte, so it shares
            // the canonical scope length of authorization_codes.scope/authorization_requests.scope.
            entity.Property(e => e.Scope)
                .HasColumnName("scope")
                .HasMaxLength(IdentityConstants.MaxOidcAllowedScopesLength);
            ConfigureInstant(entity.Property(e => e.AuthTime).HasColumnName("auth_time"));
            ConfigureInstant(entity.Property(e => e.ConsumedAt).HasColumnName("consumed_at"));
            entity.HasIndex(e => e.TokenValue).IsUnique();
            entity.HasIndex(e => e.LdapCredentialId);
            entity.HasIndex(e => e.SmsUserLoginId);
            entity.HasIndex(e => e.WechatUserLoginId);
            entity.HasIndex(e => e.FamilyId);
            entity.HasIndex(e => e.IdentitySessionId);
            // One child per parent (PS-06): the unique nullable index is what makes a second
            // child of the same consumed parent a database failure.
            entity.HasIndex(e => e.ParentId).IsUnique();
            // PS-23: the family references are restrictive; deleting a referenced root, parent,
            // or session fails and cleanup never nulls a reference to force a delete.
            entity.HasOne<RefreshTokenEntity>()
                .WithMany()
                .HasForeignKey(e => e.FamilyId)
                .OnDelete(DeleteBehavior.Restrict);
            entity.HasOne<RefreshTokenEntity>()
                .WithMany()
                .HasForeignKey(e => e.ParentId)
                .OnDelete(DeleteBehavior.Restrict);
            entity.HasOne<IdentitySessionEntity>()
                .WithMany()
                .HasForeignKey(e => e.IdentitySessionId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<AppRegistrationEntity>(entity =>
        {
            entity.ToTable("app_registrations");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AppId).HasColumnName("app_id").HasMaxLength(IdentityConstants.MaxAppIdLength);
            entity.Property(e => e.AppIdNormalized).HasColumnName("app_id_normalized").HasMaxLength(IdentityConstants.MaxAppIdLength);
            entity.Property(e => e.AppSecretHash).HasColumnName("app_secret_hash").HasMaxLength(IdentityConstants.MaxPasswordHashLength);
            entity.Property(e => e.AppName).HasColumnName("app_name").HasMaxLength(IdentityConstants.MaxAppNameLength);
            entity.Property(e => e.CallbackUrl).HasColumnName("callback_url").HasMaxLength(IdentityConstants.MaxCallbackUrlLength);
            entity.Property(e => e.IsActive).HasColumnName("is_active");
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            ConfigureInstant(entity.Property(e => e.CallbackExpiresAt).HasColumnName("callback_expires_at"));
            entity.Property(e => e.LdapLoginMode).HasColumnName("ldap_login_mode");
            entity.Property(e => e.SmsLoginMode).HasColumnName("sms_login_mode");
            entity.Property(e => e.SmsProfileKey).HasColumnName("sms_profile_key").HasMaxLength(64);
            entity.Property(e => e.WechatLoginMode).HasColumnName("wechat_login_mode");
            entity.Property(e => e.AudienceMode).HasColumnName("audience_mode");
            entity.Property(e => e.ClientType)
                .HasColumnName("client_type")
                .HasDefaultValue(OidcClientType.Confidential);
            entity.Property(e => e.AllowAuthorizationCode)
                .HasColumnName("allow_authorization_code")
                .HasDefaultValue(false);
            entity.Property(e => e.AllowedScopes)
                .HasColumnName("allowed_scopes")
                .HasMaxLength(IdentityConstants.MaxOidcAllowedScopesLength)
                .HasDefaultValue("openid");
            entity.Property(e => e.AllowRefreshToken)
                .HasColumnName("allow_refresh_token")
                .HasDefaultValue(false);
            entity.Property(e => e.IdentitySessionMaxAgeSeconds)
                .HasColumnName("identity_session_max_age_seconds");
            entity.HasIndex(e => e.AppIdNormalized).IsUnique();
        });

        modelBuilder.Entity<AppRedirectUriEntity>(entity =>
        {
            entity.ToTable("app_redirect_uris");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AppRegistrationId).HasColumnName("app_registration_id");
            entity.Property(e => e.Kind).HasColumnName("kind");
            entity.Property(e => e.CanonicalUri)
                .HasColumnName("canonical_uri")
                .HasMaxLength(IdentityConstants.MaxOidcCanonicalRedirectUriLength);
            entity.HasIndex(e => new { e.AppRegistrationId, e.Kind, e.CanonicalUri }).IsUnique();
            entity.HasOne(e => e.AppRegistration)
                .WithMany(e => e.RedirectUris)
                .HasForeignKey(e => e.AppRegistrationId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<LdapCredentialEntity>(entity =>
        {
            entity.ToTable("ldap_credentials");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            entity.Property(e => e.DirectoryKey).HasColumnName("directory_key").HasMaxLength(IdentityConstants.MaxDirectoryKeyLength);
            entity.Property(e => e.DirectoryKeyNormalized).HasColumnName("directory_key_normalized").HasMaxLength(IdentityConstants.MaxDirectoryKeyLength);
            entity.Property(e => e.ObjectGuid).HasColumnName("object_guid");
            entity.Property(e => e.UserPrincipalName).HasColumnName("user_principal_name").HasMaxLength(IdentityConstants.MaxProviderUserIdLength);
            entity.Property(e => e.UserPrincipalNameNormalized).HasColumnName("user_principal_name_normalized").HasMaxLength(IdentityConstants.MaxProviderUserIdLength);
            entity.Property(e => e.SamAccountName).HasColumnName("sam_account_name").HasMaxLength(IdentityConstants.MaxUsernameLength);
            entity.Property(e => e.SamAccountNameNormalized).HasColumnName("sam_account_name_normalized").HasMaxLength(IdentityConstants.MaxUsernameLength);
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.HasIndex(e => e.AccountId);
            entity.HasIndex(e => new { e.DirectoryKeyNormalized, e.ObjectGuid }).IsUnique();
            entity.HasIndex(e => new { e.DirectoryKeyNormalized, e.UserPrincipalNameNormalized }).IsUnique();
            entity.HasIndex(e => new { e.DirectoryKeyNormalized, e.SamAccountNameNormalized }).IsUnique();
            entity.HasOne<AccountEntity>().WithMany().HasForeignKey(e => e.AccountId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AppLdapAccessEntity>(entity =>
        {
            entity.ToTable("app_ldap_accesses");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AppRegistrationId).HasColumnName("app_registration_id");
            entity.Property(e => e.LdapCredentialId).HasColumnName("ldap_credential_id");
            entity.Property(e => e.ApprovalSource).HasColumnName("approval_source");
            entity.Property(e => e.IsActive).HasColumnName("is_active");
            entity.Property(e => e.ApprovedBy).HasColumnName("approved_by");
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.HasIndex(e => new { e.AppRegistrationId, e.LdapCredentialId }).IsUnique();
            entity.HasIndex(e => e.LdapCredentialId);
            entity.HasOne<AppRegistrationEntity>().WithMany().HasForeignKey(e => e.AppRegistrationId).OnDelete(DeleteBehavior.Cascade);
            entity.HasOne<LdapCredentialEntity>().WithMany().HasForeignKey(e => e.LdapCredentialId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AppSmsAccessEntity>(entity =>
        {
            entity.ToTable("app_sms_accesses");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AppRegistrationId).HasColumnName("app_registration_id");
            entity.Property(e => e.UserLoginId).HasColumnName("user_login_id");
            entity.Property(e => e.ApprovalSource).HasColumnName("approval_source");
            entity.Property(e => e.IsActive).HasColumnName("is_active");
            entity.Property(e => e.ApprovedBy).HasColumnName("approved_by");
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.HasIndex(e => new { e.AppRegistrationId, e.UserLoginId }).IsUnique();
            entity.HasIndex(e => e.UserLoginId);
            entity.HasOne<AppRegistrationEntity>().WithMany().HasForeignKey(e => e.AppRegistrationId).OnDelete(DeleteBehavior.Cascade);
            entity.HasOne<UserLoginEntity>().WithMany().HasForeignKey(e => e.UserLoginId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AppWechatAccessEntity>(entity =>
        {
            entity.ToTable("app_wechat_accesses");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AppRegistrationId).HasColumnName("app_registration_id");
            entity.Property(e => e.UserLoginId).HasColumnName("user_login_id");
            entity.Property(e => e.ApprovalSource).HasColumnName("approval_source");
            entity.Property(e => e.IsActive).HasColumnName("is_active");
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.HasIndex(e => new { e.AppRegistrationId, e.UserLoginId }).IsUnique();
            entity.HasIndex(e => e.UserLoginId);
            entity.HasOne<AppRegistrationEntity>().WithMany().HasForeignKey(e => e.AppRegistrationId).OnDelete(DeleteBehavior.Cascade);
            entity.HasOne<UserLoginEntity>().WithMany().HasForeignKey(e => e.UserLoginId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AppExchangeTrustEntity>(entity =>
        {
            entity.ToTable(
                "app_exchange_trusts",
                // An application trusting itself is not an edge, it is the ordinary binding check.
                // Rejecting it in the schema keeps the validator from having to reason about it.
                table => table.HasCheckConstraint(
                    "CK_app_exchange_trusts_no_self_trust",
                    "app_registration_id <> source_app_registration_id"));
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AppRegistrationId).HasColumnName("app_registration_id");
            entity.Property(e => e.SourceAppRegistrationId).HasColumnName("source_app_registration_id");
            entity.Property(e => e.ApprovedBy).HasColumnName("approved_by");
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.HasIndex(e => new { e.AppRegistrationId, e.SourceAppRegistrationId }).IsUnique();
            entity.HasIndex(e => e.SourceAppRegistrationId);
            // An edge has no meaning without either endpoint, so deleting an application removes the
            // edges pointing at it from both directions.
            entity.HasOne<AppRegistrationEntity>().WithMany().HasForeignKey(e => e.AppRegistrationId).OnDelete(DeleteBehavior.Cascade);
            entity.HasOne<AppRegistrationEntity>().WithMany().HasForeignKey(e => e.SourceAppRegistrationId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AuthorizationRequestEntity>(entity =>
        {
            entity.ToTable("authorization_requests");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.HandleDigest)
                .HasColumnName("handle_digest")
                .HasMaxLength(LoginHandleDigest.EncodedLength)
                .IsRequired();
            entity.Property(e => e.AppRegistrationId).HasColumnName("app_registration_id");
            entity.Property(e => e.RedirectUri)
                .HasColumnName("redirect_uri")
                .HasMaxLength(IdentityConstants.MaxOidcCanonicalRedirectUriLength)
                .IsRequired();
            entity.Property(e => e.Scope)
                .HasColumnName("scope")
                .HasMaxLength(IdentityConstants.MaxOidcAllowedScopesLength)
                .IsRequired();
            entity.Property(e => e.State)
                .HasColumnName("state")
                .HasMaxLength(IdentityConstants.MaxOidcOpaqueValueLength)
                .IsRequired();
            entity.Property(e => e.Nonce)
                .HasColumnName("nonce")
                .HasMaxLength(IdentityConstants.MaxOidcOpaqueValueLength)
                .IsRequired();
            entity.Property(e => e.CodeChallenge)
                .HasColumnName("code_challenge")
                .HasMaxLength(IdentityConstants.MaxOidcCodeChallengeLength)
                .IsRequired();
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            ConfigureInstant(entity.Property(e => e.ExpiresAt).HasColumnName("expires_at"));
            ConfigureInstant(entity.Property(e => e.ConsumedAt).HasColumnName("consumed_at"));
            entity.HasIndex(e => e.HandleDigest).IsUnique();
            // PS-23: the client reference is restrictive and non-nullable, created together with this
            // table, so a stored continuation can never name a client the schema cannot resolve.
            // Deleting an application with live continuation rows fails; cleanup deletes rows by
            // retention and never nulls this reference.
            entity.HasOne<AppRegistrationEntity>()
                .WithMany()
                .HasForeignKey(e => e.AppRegistrationId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<IdentitySessionEntity>(entity =>
        {
            entity.ToTable(
                "identity_sessions",
                // The revocation fact is one pair: a reason without a time, or a time without a
                // reason, is not a revocation. The check enforces the pairing on both providers;
                // the closed value set itself stays a domain rule so later canonical events can
                // add reasons without a schema change.
                table => table.HasCheckConstraint(
                    "CK_identity_sessions_revocation_pair",
                    "(revoked_at IS NULL AND revocation_reason IS NULL) "
                    + "OR (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)"));
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            entity.Property(e => e.PasswordCredentialId).HasColumnName("password_credential_id");
            entity.Property(e => e.AuthMethod)
                .HasColumnName("auth_method")
                .HasMaxLength(IdentityConstants.MaxAuthMethodLength)
                .IsRequired();
            ConfigureInstant(entity.Property(e => e.AuthTime).HasColumnName("auth_time"));
            ConfigureInstant(entity.Property(e => e.LastSeenAt).HasColumnName("last_seen_at"));
            ConfigureInstant(entity.Property(e => e.IdleExpiresAt).HasColumnName("idle_expires_at"));
            ConfigureInstant(entity.Property(e => e.AbsoluteExpiresAt).HasColumnName("absolute_expires_at"));
            ConfigureInstant(entity.Property(e => e.RevokedAt).HasColumnName("revoked_at"));
            entity.Property(e => e.RevocationReason)
                .HasColumnName("revocation_reason")
                .HasMaxLength(IdentityConstants.MaxIdentitySessionRevocationReasonLength);
            entity.HasIndex(e => e.AccountId);
            entity.HasIndex(e => e.PasswordCredentialId);
            // PS-23: both identity references are restrictive and non-nullable, created together
            // with this table, so a live session can never name an account or credential the
            // schema cannot resolve. Deleting a referenced account or password credential fails;
            // cleanup deletes rows only by retention and never nulls a reference.
            entity.HasOne<AccountEntity>()
                .WithMany()
                .HasForeignKey(e => e.AccountId)
                .OnDelete(DeleteBehavior.Restrict);
            entity.HasOne<PasswordCredentialEntity>()
                .WithMany()
                .HasForeignKey(e => e.PasswordCredentialId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<AuthorizationCodeEntity>(entity =>
        {
            entity.ToTable(
                "authorization_codes",
                // PS-05: the interactive refresh family link (#97/#98) may only appear on a
                // consumed row — it is written together with the first redemption (EV-21). The
                // check enforces the pairing on both providers.
                table => table.HasCheckConstraint(
                    "CK_authorization_codes_family_requires_consumption",
                    "refresh_family_id IS NULL OR consumed_at IS NOT NULL"));
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.CodeDigest)
                .HasColumnName("code_digest")
                .HasMaxLength(AuthorizationCodeDigest.EncodedLength)
                .IsRequired();
            entity.Property(e => e.AppRegistrationId).HasColumnName("app_registration_id");
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            entity.Property(e => e.IdentitySessionId).HasColumnName("identity_session_id");
            entity.Property(e => e.RedirectUri)
                .HasColumnName("redirect_uri")
                .HasMaxLength(IdentityConstants.MaxOidcCanonicalRedirectUriLength)
                .IsRequired();
            entity.Property(e => e.Scope)
                .HasColumnName("scope")
                .HasMaxLength(IdentityConstants.MaxOidcAllowedScopesLength)
                .IsRequired();
            entity.Property(e => e.Nonce)
                .HasColumnName("nonce")
                .HasMaxLength(IdentityConstants.MaxOidcOpaqueValueLength)
                .IsRequired();
            entity.Property(e => e.CodeChallenge)
                .HasColumnName("code_challenge")
                .HasMaxLength(IdentityConstants.MaxOidcCodeChallengeLength)
                .IsRequired();
            ConfigureInstant(entity.Property(e => e.AuthTime).HasColumnName("auth_time"));
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            ConfigureInstant(entity.Property(e => e.ExpiresAt).HasColumnName("expires_at"));
            ConfigureInstant(entity.Property(e => e.ConsumedAt).HasColumnName("consumed_at"));
            // PS-23's single reserved exception, now resolved: #50 created the family-link column
            // without a reference because no family root shape existed; the family migration adds
            // the restrictive reference and its index after the legacy backfill, and #98 writes
            // the values.
            entity.Property(e => e.RefreshFamilyId).HasColumnName("refresh_family_id");
            entity.HasIndex(e => e.CodeDigest).IsUnique();
            entity.HasIndex(e => e.IdentitySessionId);
            entity.HasIndex(e => e.RefreshFamilyId);
            // PS-23: all three non-null references are restrictive and were created together with
            // this table, and the nullable family link resolves the root it names; deleting a
            // referenced row fails, and cleanup deletes code rows by retention without ever
            // nulling a reference.
            entity.HasOne<AppRegistrationEntity>()
                .WithMany()
                .HasForeignKey(e => e.AppRegistrationId)
                .OnDelete(DeleteBehavior.Restrict);
            entity.HasOne<AccountEntity>()
                .WithMany()
                .HasForeignKey(e => e.AccountId)
                .OnDelete(DeleteBehavior.Restrict);
            entity.HasOne<IdentitySessionEntity>()
                .WithMany()
                .HasForeignKey(e => e.IdentitySessionId)
                .OnDelete(DeleteBehavior.Restrict);
            entity.HasOne<RefreshTokenEntity>()
                .WithMany()
                .HasForeignKey(e => e.RefreshFamilyId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<LogoutRequestEntity>(entity =>
        {
            entity.ToTable("logout_requests");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.HandleDigest)
                .HasColumnName("handle_digest")
                .HasMaxLength(LoginHandleDigest.EncodedLength)
                .IsRequired();
            entity.Property(e => e.AppRegistrationId).HasColumnName("app_registration_id");
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            entity.Property(e => e.IdentitySessionId).HasColumnName("identity_session_id");
            entity.Property(e => e.PostLogoutRedirectUri)
                .HasColumnName("post_logout_redirect_uri")
                .HasMaxLength(IdentityConstants.MaxOidcCanonicalRedirectUriLength);
            entity.Property(e => e.State)
                .HasColumnName("state")
                .HasMaxLength(IdentityConstants.MaxLogoutStateLength);
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            ConfigureInstant(entity.Property(e => e.ExpiresAt).HasColumnName("expires_at"));
            ConfigureInstant(entity.Property(e => e.ConsumedAt).HasColumnName("consumed_at"));
            entity.HasIndex(e => e.HandleDigest).IsUnique();
            // PS-08: only the client reference is referential — restrictive, non-nullable, created
            // together with this table. The account and session values are snapshots the
            // completion compares against live rows (IN-36); a session row may legitimately be
            // gone by then, and EV-07 handles that without a state write, so no referential
            // constraint may forbid the state.
            entity.HasOne<AppRegistrationEntity>()
                .WithMany()
                .HasForeignKey(e => e.AppRegistrationId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<OidcRateLimitBucketEntity>(entity =>
        {
            entity.ToTable("oidc_rate_limit_buckets", table =>
            {
                table.HasCheckConstraint("CK_oidc_rate_limit_buckets_policy",
                    "policy IN ('oidc-authorize', 'oidc-login', 'oidc-token', 'oidc-userinfo', 'oidc-logout', 'oidc-revoke')");
                table.HasCheckConstraint("CK_oidc_rate_limit_buckets_digest_length", "length(partition_digest) = 64");
                table.HasCheckConstraint("CK_oidc_rate_limit_buckets_permit_count", "permit_count BETWEEN 1 AND 90");
            });
            entity.HasKey(e => new { e.Policy, e.PartitionDigest });
            entity.Property(e => e.Policy).HasColumnName("policy").HasMaxLength(32);
            entity.Property(e => e.PartitionDigest).HasColumnName("partition_digest").HasMaxLength(64);
            ConfigureInstant(entity.Property(e => e.WindowExpiresAt).HasColumnName("window_expires_at"));
            entity.Property(e => e.PermitCount).HasColumnName("permit_count");
            entity.HasIndex(e => e.WindowExpiresAt);
        });

        modelBuilder.Entity<SecurityKeyEntity>(entity =>
        {
            entity.ToTable("security_keys");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.KeyId).HasColumnName("key_id").HasMaxLength(IdentityConstants.MaxKeyNameLength);
            entity.Property(e => e.PublicKeyExponent).HasColumnName("public_key_exponent").HasMaxLength(IdentityConstants.MaxEncryptedKeyLength);
            entity.Property(e => e.PublicKeyModulus).HasColumnName("public_key_modulus").HasMaxLength(IdentityConstants.MaxPublicKeyModulusLength);
            entity.Property(e => e.EncryptedPrivateKeyParams).HasColumnName("encrypted_private_key_params").HasMaxLength(IdentityConstants.MaxEncryptedKeyLength);
            entity.Property(e => e.EncryptionSalt).HasColumnName("encryption_salt").HasMaxLength(IdentityConstants.MaxEncryptionSaltLength);
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            ConfigureInstant(entity.Property(e => e.ExpiresAt).HasColumnName("expires_at"));
            entity.Property(e => e.IsActive).HasColumnName("is_active");
            entity.HasIndex(e => e.KeyId).IsUnique();
        });

        modelBuilder.Entity<OtpEntity>(entity =>
        {
            entity.ToTable("otps");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AppRegistrationId).HasColumnName("app_registration_id");
            entity.Property(e => e.Phone).HasColumnName("phone").HasMaxLength(20);
            entity.Property(e => e.CodeMac).HasColumnName("code_mac").HasMaxLength(64);
            entity.Property(e => e.Status).HasColumnName("status");
            ConfigureInstant(entity.Property(e => e.ExpiresAt).HasColumnName("expires_at"));
            entity.Property(e => e.Attempts).HasColumnName("attempts");
            ConfigureInstant(entity.Property(e => e.LockoutUntil).HasColumnName("lockout_until"));
            ConfigureInstant(entity.Property(e => e.HourWindowStartedAt).HasColumnName("hour_window_started_at"));
            entity.Property(e => e.HourSendCount).HasColumnName("hour_send_count");
            ConfigureInstant(entity.Property(e => e.DayWindowStartedAt).HasColumnName("day_window_started_at"));
            entity.Property(e => e.DaySendCount).HasColumnName("day_send_count");
            entity.Property(e => e.Provider).HasColumnName("provider").HasMaxLength(32);
            entity.Property(e => e.ProfileKey).HasColumnName("profile_key").HasMaxLength(64);
            entity.Property(e => e.ProviderMessageId).HasColumnName("provider_message_id").HasMaxLength(128);
            ConfigureInstant(entity.Property(e => e.SentAt).HasColumnName("sent_at"));
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.Property(e => e.Version).HasColumnName("version").IsConcurrencyToken();
            entity.HasIndex(e => new { e.AppRegistrationId, e.Phone }).IsUnique();
            entity.HasOne<AppRegistrationEntity>().WithMany().HasForeignKey(e => e.AppRegistrationId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<LoginAttemptEntity>(entity =>
        {
            entity.ToTable("login_attempts");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.Username).HasColumnName("username").HasMaxLength(IdentityConstants.MaxUsernameLength);
            entity.Property(e => e.UsernameNormalized).HasColumnName("username_normalized").HasMaxLength(IdentityConstants.MaxUsernameLength);
            ConfigureInstant(entity.Property(e => e.LastAttemptAt).HasColumnName("last_attempt_at"));
            entity.Property(e => e.FailedAttempts).HasColumnName("failed_attempts");
            ConfigureInstant(entity.Property(e => e.LockoutUntil).HasColumnName("lockout_until"));
            entity.HasIndex(e => e.UsernameNormalized).IsUnique();
        });

        modelBuilder.Entity<LoginHistoryEntity>(entity =>
        {
            entity.ToTable("login_histories");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            entity.Property(e => e.Username).HasColumnName("username").HasMaxLength(IdentityConstants.MaxUsernameLength);
            entity.Property(e => e.AuthMethod).HasColumnName("auth_method").HasMaxLength(IdentityConstants.MaxAuthMethodLength);
            entity.Property(e => e.EventType).HasColumnName("event_type").HasMaxLength(IdentityConstants.MaxEventTypeLength);
            entity.Property(e => e.ClientIp).HasColumnName("client_ip").HasMaxLength(IdentityConstants.MaxClientIpLength);
            entity.Property(e => e.UserAgent).HasColumnName("user_agent").HasMaxLength(IdentityConstants.MaxUserAgentLength);
            entity.Property(e => e.FailureReason).HasColumnName("failure_reason").HasMaxLength(IdentityConstants.MaxFailureReasonLength);
            entity.Property(e => e.AppId).HasColumnName("app_id").HasMaxLength(IdentityConstants.MaxAppIdLength);
            entity.Property(e => e.CorrelationId).HasColumnName("correlation_id").HasMaxLength(64);
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.HasIndex(e => e.AccountId);
            entity.HasIndex(e => e.CreatedAt);
            entity.HasIndex(e => e.ClientIp);
        });

        // ServiceMantle shared installation mapping (service_installations). Applied last so it never
        // interferes with the SignaCore-owned configuration above. ServiceInstallationEntity uses
        // DateTime, so its *_at_utc columns keep the library's provider-default storage rather than
        // the SignaCore DateTimeOffset/Unix-microseconds convention; this is intentional and isolated
        // to the service_installations table.
        modelBuilder.AddServiceMantleInstallation();

        // ServiceMantle shared Data Protection key ring (service_data_protection_keys): the only
        // key store, shared by every cookie the host issues. Keys are stored as service-bound
        // encrypted envelopes; the legacy data_protection_keys table was removed with its
        // forward drop migration.
        modelBuilder.AddServiceMantleDataProtectionKeys();

        // Shared setting stack: the single-aggregate service_settings row and the shared
        // service_audit_logs table. Both follow the library's provider-default DateTime storage.
        // The audit dialect mirrors the ConfigureInstant provider branch: the migrations of both
        // providers map the same model with their own dialect.
        modelBuilder.AddServiceMantleSettings();
        modelBuilder.AddServiceMantleManagementAudit(
            string.Equals(
                Database.ProviderName,
                "Microsoft.EntityFrameworkCore.Sqlite",
                StringComparison.Ordinal)
                ? ManagementAuditDatabaseDialect.Sqlite
                : ManagementAuditDatabaseDialect.PostgreSql);

        ConfigurePostgreSqlLegacyTextColumns(modelBuilder);
    }

    /// <summary>
    /// The 28 PostgreSQL columns the early migrations created as <c>TEXT</c> with a
    /// <c>maxLength</c> the runtime never enforced. The model now states the physical fact
    /// (<c>text</c>) for exactly these columns — the <c>HasMaxLength</c> metadata above stays
    /// untouched — so the snapshot and every future generated <c>AlterColumn</c> stop disagreeing
    /// with real databases. SQLite is unaffected: its model, snapshot, and history keep the same
    /// shape. New columns must never be added here; the current model creates them as
    /// <c>varchar(N)</c> and they are born consistent.
    /// </summary>
    private static readonly (Type Entity, string Property)[] PostgreSqlLegacyTextColumns =
    [
        (typeof(AccountEntity), nameof(AccountEntity.LastLoginIp)),
        (typeof(AccountEntity), nameof(AccountEntity.LastLoginMethod)),
        (typeof(AccountEntity), nameof(AccountEntity.Nickname)),
        (typeof(AccountEntity), nameof(AccountEntity.Remark)),
        (typeof(AppRegistrationEntity), nameof(AppRegistrationEntity.AppId)),
        (typeof(AppRegistrationEntity), nameof(AppRegistrationEntity.AppName)),
        (typeof(AppRegistrationEntity), nameof(AppRegistrationEntity.AppSecretHash)),
        (typeof(AppRegistrationEntity), nameof(AppRegistrationEntity.CallbackUrl)),
        (typeof(LoginAttemptEntity), nameof(LoginAttemptEntity.Username)),
        (typeof(LoginHistoryEntity), nameof(LoginHistoryEntity.AppId)),
        (typeof(LoginHistoryEntity), nameof(LoginHistoryEntity.AuthMethod)),
        (typeof(LoginHistoryEntity), nameof(LoginHistoryEntity.ClientIp)),
        (typeof(LoginHistoryEntity), nameof(LoginHistoryEntity.CorrelationId)),
        (typeof(LoginHistoryEntity), nameof(LoginHistoryEntity.EventType)),
        (typeof(LoginHistoryEntity), nameof(LoginHistoryEntity.FailureReason)),
        (typeof(LoginHistoryEntity), nameof(LoginHistoryEntity.UserAgent)),
        (typeof(LoginHistoryEntity), nameof(LoginHistoryEntity.Username)),
        (typeof(OtpEntity), nameof(OtpEntity.Phone)),
        (typeof(PasswordCredentialEntity), nameof(PasswordCredentialEntity.PasswordHash)),
        (typeof(PasswordCredentialEntity), nameof(PasswordCredentialEntity.Username)),
        (typeof(RefreshTokenEntity), nameof(RefreshTokenEntity.TokenValue)),
        (typeof(SecurityKeyEntity), nameof(SecurityKeyEntity.EncryptedPrivateKeyParams)),
        (typeof(SecurityKeyEntity), nameof(SecurityKeyEntity.EncryptionSalt)),
        (typeof(SecurityKeyEntity), nameof(SecurityKeyEntity.KeyId)),
        (typeof(SecurityKeyEntity), nameof(SecurityKeyEntity.PublicKeyExponent)),
        (typeof(SecurityKeyEntity), nameof(SecurityKeyEntity.PublicKeyModulus)),
        (typeof(UserLoginEntity), nameof(UserLoginEntity.ProviderName)),
        (typeof(UserLoginEntity), nameof(UserLoginEntity.ProviderUserId))
    ];

    /// <summary>
    /// Aligns the PostgreSQL model's column types with the physical schema the early migrations
    /// created. Mirrors the <see cref="ConfigureInstant"/> provider branch: SQLite returns
    /// unchanged, and the <c>text</c> type is a metadata statement only — no runtime SQL,
    /// parameter typing, read, or write behavior changes on either provider.
    /// </summary>
    private void ConfigurePostgreSqlLegacyTextColumns(ModelBuilder modelBuilder)
    {
        if (string.Equals(
                Database.ProviderName,
                "Microsoft.EntityFrameworkCore.Sqlite",
                StringComparison.Ordinal))
        {
            return;
        }

        foreach (var (entity, property) in PostgreSqlLegacyTextColumns)
        {
            modelBuilder.Entity(entity)
                .Property(property)
                .HasColumnType("text");
        }
    }

    private void ConfigureInstant(PropertyBuilder property)
    {
        var providerName = Database.ProviderName;

        if (string.Equals(
            providerName,
            "Microsoft.EntityFrameworkCore.Sqlite",
            StringComparison.Ordinal))
        {
            property.HasConversion(UnixMicrosecondsConverter);
            return;
        }

        property.HasColumnType("timestamptz");
    }

    private void ApplyNormalizedValues()
    {
        foreach (var entry in ChangeTracker.Entries<AccountEntity>()
                     .Where(entry => entry.State is EntityState.Added or EntityState.Modified))
        {
            entry.Entity.NicknameNormalized =
                IdentityValueNormalizer.NormalizeNullable(entry.Entity.Nickname);
            entry.Entity.RemarkNormalized =
                IdentityValueNormalizer.NormalizeNullable(entry.Entity.Remark);
        }

        foreach (var entry in ChangeTracker.Entries<PasswordCredentialEntity>()
                     .Where(entry => entry.State is EntityState.Added or EntityState.Modified))
        {
            entry.Entity.UsernameNormalized =
                IdentityValueNormalizer.Normalize(entry.Entity.Username);
        }

        foreach (var entry in ChangeTracker.Entries<LoginAttemptEntity>()
                     .Where(entry => entry.State is EntityState.Added or EntityState.Modified))
        {
            entry.Entity.UsernameNormalized =
                IdentityValueNormalizer.Normalize(entry.Entity.Username);
        }

        foreach (var entry in ChangeTracker.Entries<AppRegistrationEntity>()
                     .Where(entry => entry.State is EntityState.Added or EntityState.Modified))
        {
            entry.Entity.AppIdNormalized =
                IdentityValueNormalizer.Normalize(entry.Entity.AppId);
        }

        foreach (var entry in ChangeTracker.Entries<UserLoginEntity>()
                     .Where(entry => entry.State is EntityState.Added or EntityState.Modified))
        {
            entry.Entity.ProviderNameNormalized =
                IdentityValueNormalizer.Normalize(entry.Entity.ProviderName);
        }

        foreach (var entry in ChangeTracker.Entries<LdapCredentialEntity>()
                     .Where(entry => entry.State is EntityState.Added or EntityState.Modified))
        {
            entry.Entity.DirectoryKeyNormalized = IdentityValueNormalizer.Normalize(entry.Entity.DirectoryKey);
            entry.Entity.UserPrincipalNameNormalized = IdentityValueNormalizer.Normalize(entry.Entity.UserPrincipalName);
            entry.Entity.SamAccountNameNormalized = IdentityValueNormalizer.Normalize(entry.Entity.SamAccountName);
        }
    }
}
