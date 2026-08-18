using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using SignaCore.Database.Entity;

namespace SignaCore.Database;

public class IdentityDbContext : DbContext
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
    public DbSet<SecurityKeyEntity> SecurityKeys => Set<SecurityKeyEntity>();
    public DbSet<OtpEntity> Otps => Set<OtpEntity>();
    public DbSet<LoginAttemptEntity> LoginAttempts => Set<LoginAttemptEntity>();
    public DbSet<LoginHistoryEntity> LoginHistories => Set<LoginHistoryEntity>();
    public DbSet<AuditLogEntity> AuditLogs => Set<AuditLogEntity>();
    public DbSet<LdapCredentialEntity> LdapCredentials => Set<LdapCredentialEntity>();
    public DbSet<AppLdapAccessEntity> AppLdapAccesses => Set<AppLdapAccessEntity>();
    public DbSet<AppSmsAccessEntity> AppSmsAccesses => Set<AppSmsAccessEntity>();
    public DbSet<AppWechatAccessEntity> AppWechatAccesses => Set<AppWechatAccessEntity>();
    public DbSet<AppExchangeTrustEntity> AppExchangeTrusts => Set<AppExchangeTrustEntity>();
    public DbSet<SystemSettingEntity> SystemSettings => Set<SystemSettingEntity>();
    public DbSet<InstallationStateEntity> InstallationStates => Set<InstallationStateEntity>();

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
                table => table.HasCheckConstraint(
                    "CK_refresh_tokens_app_id_not_empty",
                    "app_id <> ''"));
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
            entity.HasIndex(e => e.TokenValue).IsUnique();
            entity.HasIndex(e => e.LdapCredentialId);
            entity.HasIndex(e => e.SmsUserLoginId);
            entity.HasIndex(e => e.WechatUserLoginId);
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
            entity.HasIndex(e => e.AppIdNormalized).IsUnique();
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

        modelBuilder.Entity<AuditLogEntity>(entity =>
        {
            entity.ToTable("audit_logs");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.Action).HasColumnName("action").HasMaxLength(IdentityConstants.MaxAuditActionLength);
            entity.Property(e => e.TargetType).HasColumnName("target_type").HasMaxLength(IdentityConstants.MaxAuditTargetTypeLength);
            entity.Property(e => e.TargetId).HasColumnName("target_id").HasMaxLength(64);
            entity.Property(e => e.ActorId).HasColumnName("actor_id");
            entity.Property(e => e.ActorName).HasColumnName("actor_name").HasMaxLength(IdentityConstants.MaxUsernameLength);
            entity.Property(e => e.BeforeSnapshot).HasColumnName("before_snapshot").HasMaxLength(IdentityConstants.MaxSnapshotLength);
            entity.Property(e => e.AfterSnapshot).HasColumnName("after_snapshot").HasMaxLength(IdentityConstants.MaxSnapshotLength);
            entity.Property(e => e.Description).HasColumnName("description").HasMaxLength(IdentityConstants.MaxAuditDescriptionLength);
            entity.Property(e => e.ClientIp).HasColumnName("client_ip").HasMaxLength(IdentityConstants.MaxClientIpLength);
            entity.Property(e => e.CorrelationId).HasColumnName("correlation_id").HasMaxLength(64);
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.HasIndex(e => new { e.TargetType, e.TargetId, e.CreatedAt });
            entity.HasIndex(e => new { e.ActorId, e.CreatedAt });
            entity.HasIndex(e => new { e.Action, e.CreatedAt });
            entity.HasIndex(e => e.CreatedAt);
        });

        modelBuilder.Entity<SystemSettingEntity>(entity =>
        {
            entity.ToTable("system_settings");
            entity.HasKey(e => e.Key);
            entity.Property(e => e.Key).HasColumnName("key").HasMaxLength(IdentityConstants.MaxSettingKeyLength);
            // No length limit: structured settings such as Ldap:Directories serialize to JSON that
            // easily exceeds any varchar bound the three providers agree on.
            entity.Property(e => e.Value).HasColumnName("value").IsRequired();
            entity.Property(e => e.ValueType).HasColumnName("value_type").HasMaxLength(IdentityConstants.MaxSettingValueTypeLength);
            entity.Property(e => e.IsSecret).HasColumnName("is_secret");
            entity.Property(e => e.Version).HasColumnName("version");
            ConfigureInstant(entity.Property(e => e.UpdatedAt).HasColumnName("updated_at"));
            entity.Property(e => e.UpdatedBy).HasColumnName("updated_by").HasMaxLength(IdentityConstants.MaxUsernameLength);
        });

        modelBuilder.Entity<InstallationStateEntity>(entity =>
        {
            entity.ToTable(
                "installation_state",
                table => table.HasCheckConstraint(
                    "CK_installation_state_singleton",
                    "id = 1"));
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id").ValueGeneratedNever();
            entity.Property(e => e.Status).HasColumnName("status");
            entity.Property(e => e.InstallationId).HasColumnName("installation_id");
            entity.Property(e => e.SetupCodeHash).HasColumnName("setup_code_hash").HasMaxLength(IdentityConstants.MaxSetupCodeHashLength);
            ConfigureInstant(entity.Property(e => e.SetupCodeExpiresAt).HasColumnName("setup_code_expires_at"));
            ConfigureInstant(entity.Property(e => e.CompletedAt).HasColumnName("completed_at"));
            entity.Property(e => e.ConfigurationVersion).HasColumnName("configuration_version");
        });
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
