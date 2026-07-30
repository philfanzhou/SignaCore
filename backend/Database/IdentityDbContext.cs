using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database;

public class IdentityDbContext : DbContext
{
    private static readonly ValueConverter<DateTimeOffset, DateTime> UtcDateTimeConverter = new(
        value => value.UtcDateTime,
        value => new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)));

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

        if (string.Equals(
            Database.ProviderName,
            "Pomelo.EntityFrameworkCore.MySql",
            StringComparison.Ordinal))
        {
            modelBuilder
                .HasCharSet("utf8mb4")
                .UseCollation("utf8mb4_bin");
        }

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
            entity.ToTable("refresh_tokens");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            entity.Property(e => e.TokenValue).HasColumnName("token_value").HasMaxLength(IdentityConstants.MaxRefreshTokenLength);
            ConfigureInstant(entity.Property(e => e.ExpiresAt).HasColumnName("expires_at"));
            entity.Property(e => e.IsRevoked).HasColumnName("is_revoked");
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.Property(e => e.AppId).HasColumnName("app_id").HasMaxLength(IdentityConstants.MaxAppIdLength);
            entity.HasIndex(e => e.TokenValue).IsUnique();
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
            entity.HasIndex(e => e.AppIdNormalized).IsUnique();
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
            entity.Property(e => e.Phone).HasColumnName("phone").HasMaxLength(20);
            entity.Property(e => e.Code).HasColumnName("code").HasMaxLength(10);
            ConfigureInstant(entity.Property(e => e.ExpiresAt).HasColumnName("expires_at"));
            entity.Property(e => e.Attempts).HasColumnName("attempts");
            ConfigureInstant(entity.Property(e => e.LockoutUntil).HasColumnName("lockout_until"));
            ConfigureInstant(entity.Property(e => e.CreatedAt).HasColumnName("created_at"));
            entity.HasIndex(e => e.Phone).IsUnique();
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

        if (string.Equals(
            providerName,
            "Pomelo.EntityFrameworkCore.MySql",
            StringComparison.Ordinal))
        {
            property
                .HasConversion(UtcDateTimeConverter)
                .HasColumnType("datetime(6)")
                .HasPrecision(6);
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
    }
}
