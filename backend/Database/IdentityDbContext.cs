using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database.Entity;
namespace QuantumZhou.Identity.Database;

public class IdentityDbContext : DbContext
{
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

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AccountEntity>(entity =>
        {
            entity.ToTable("accounts");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.IsActive).HasColumnName("is_active");
            entity.Property(e => e.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz");
            entity.Property(e => e.Remark).HasColumnName("remark").HasMaxLength(IdentityConstants.MaxRemarkLength);
            entity.Property(e => e.Nickname).HasColumnName("nickname").HasMaxLength(IdentityConstants.MaxNicknameLength);
            entity.Property(e => e.LastLoginAt).HasColumnName("last_login_at").HasColumnType("timestamptz");
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
            entity.Property(e => e.PasswordHash).HasColumnName("password_hash").HasMaxLength(IdentityConstants.MaxPasswordHashLength);
            entity.Property(e => e.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz");
            entity.HasIndex(e => e.Username).IsUnique();
            entity.HasIndex(e => e.AccountId);
        });

        modelBuilder.Entity<UserLoginEntity>(entity =>
        {
            entity.ToTable("user_logins");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            entity.Property(e => e.ProviderName).HasColumnName("provider_name").HasMaxLength(IdentityConstants.MaxProviderNameLength);
            entity.Property(e => e.ProviderUserId).HasColumnName("provider_user_id").HasMaxLength(IdentityConstants.MaxProviderUserIdLength);
            entity.HasIndex(e => new { e.ProviderName, e.ProviderUserId }).IsUnique();
            entity.HasIndex(e => e.AccountId);
        });

        modelBuilder.Entity<RefreshTokenEntity>(entity =>
        {
            entity.ToTable("refresh_tokens");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AccountId).HasColumnName("account_id");
            entity.Property(e => e.TokenValue).HasColumnName("token_value").HasMaxLength(IdentityConstants.MaxRefreshTokenLength);
            entity.Property(e => e.ExpiresAt).HasColumnName("expires_at").HasColumnType("timestamptz");
            entity.Property(e => e.IsRevoked).HasColumnName("is_revoked");
            entity.Property(e => e.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz");
            entity.Property(e => e.AppId).HasColumnName("app_id").HasMaxLength(IdentityConstants.MaxAppIdLength);
            entity.HasIndex(e => e.TokenValue).IsUnique();
        });

        modelBuilder.Entity<AppRegistrationEntity>(entity =>
        {
            entity.ToTable("app_registrations");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AppId).HasColumnName("app_id").HasMaxLength(IdentityConstants.MaxAppIdLength);
            entity.Property(e => e.AppSecretHash).HasColumnName("app_secret_hash").HasMaxLength(IdentityConstants.MaxPasswordHashLength);
            entity.Property(e => e.AppName).HasColumnName("app_name").HasMaxLength(IdentityConstants.MaxAppNameLength);
            entity.Property(e => e.CallbackUrl).HasColumnName("callback_url").HasMaxLength(IdentityConstants.MaxCallbackUrlLength);
            entity.Property(e => e.IsActive).HasColumnName("is_active");
            entity.Property(e => e.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz");
            entity.Property(e => e.CallbackExpiresAt).HasColumnName("callback_expires_at").HasColumnType("timestamptz");
            entity.HasIndex(e => e.AppId).IsUnique();
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
            entity.Property(e => e.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz");
            entity.Property(e => e.ExpiresAt).HasColumnName("expires_at").HasColumnType("timestamptz");
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
            entity.Property(e => e.ExpiresAt).HasColumnName("expires_at").HasColumnType("timestamptz");
            entity.Property(e => e.Attempts).HasColumnName("attempts");
            entity.Property(e => e.LockoutUntil).HasColumnName("lockout_until").HasColumnType("timestamptz");
            entity.Property(e => e.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz");
            entity.HasIndex(e => e.Phone);
        });

        modelBuilder.Entity<LoginAttemptEntity>(entity =>
        {
            entity.ToTable("login_attempts");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.Username).HasColumnName("username").HasMaxLength(IdentityConstants.MaxUsernameLength);
            entity.Property(e => e.LastAttemptAt).HasColumnName("last_attempt_at").HasColumnType("timestamptz");
            entity.Property(e => e.FailedAttempts).HasColumnName("failed_attempts");
            entity.Property(e => e.LockoutUntil).HasColumnName("lockout_until").HasColumnType("timestamptz");
            entity.HasIndex(e => e.Username).IsUnique();
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
            entity.Property(e => e.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz");
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
            entity.Property(e => e.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz");
            entity.HasIndex(e => new { e.TargetType, e.TargetId, e.CreatedAt });
            entity.HasIndex(e => new { e.ActorId, e.CreatedAt });
            entity.HasIndex(e => new { e.Action, e.CreatedAt });
            entity.HasIndex(e => e.CreatedAt);
        });
    }
}
