using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Validators;

namespace QuantumZhou.Identity.Host;

internal static class DatabaseInitializer
{
    public static async Task InitializeAsync(
        IServiceProvider serviceProvider,
        string dbProvider,
        IConfiguration configuration)
    {
        var logger = serviceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("QuantumZhou.Identity.Host.DatabaseInitializer");

        using (var scope = serviceProvider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var adminBootstrapOptions = scope.ServiceProvider.GetRequiredService<IOptions<AdminBootstrapOptions>>().Value;
            var passwordPolicy = scope.ServiceProvider.GetRequiredService<IPasswordPolicy>();
            var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            try
            {
                try
                {
                    var connection = db.Database.GetDbConnection();
                    await connection.OpenAsync();

                    try
                    {
                        var missingColumns = new List<(string Table, string Column, string Definition)>
                        {
                            ("accounts", "nickname", "TEXT"),
                        };

                        foreach (var (table, column, definition) in missingColumns)
                        {
                            bool columnExists = false;
                            using (var cmd = connection.CreateCommand())
                            {
                                cmd.CommandText = $"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = CURRENT_SCHEMA() AND table_name = '{table}' AND column_name = '{column}'";
                                var r = await cmd.ExecuteScalarAsync();
                                columnExists = r != null && Convert.ToInt64(r) > 0;
                            }

                            if (!columnExists)
                            {
                                bool tableExists = false;
                                using (var cmd = connection.CreateCommand())
                                {
                                    cmd.CommandText = $"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = '{table}'";
                                    var r = await cmd.ExecuteScalarAsync();
                                    tableExists = r != null && Convert.ToInt64(r) > 0;
                                }

                                if (tableExists)
                                {
                                    try
                                    {
                                        using var cmd = connection.CreateCommand();
                                        cmd.CommandText = $"ALTER TABLE \"{table}\" ADD COLUMN \"{column}\" {definition}";
                                        await cmd.ExecuteNonQueryAsync();
                                        logger.LogInformation("Reconciled missing column: {Table}.{Column}", table, column);
                                    }
                                    catch (Exception colEx)
                                    {
                                        logger.LogWarning(colEx, "Column {Table}.{Column} may already exist, skipping", table, column);
                                    }
                                }
                            }
                        }
                    }
                    finally
                    {
                        await connection.CloseAsync();
                    }
                }
                catch (Exception reconEx)
                {
                    logger.LogWarning(reconEx, "Schema reconciliation check skipped");
                }

                {
                    var pendingMigrations = db.Database.GetPendingMigrations().ToList();
                    if (pendingMigrations.Any())
                    {
                        var appliedMigrations = db.Database.GetAppliedMigrations();
                        if (!appliedMigrations.Any())
                        {
                            try
                            {
                                var connection = db.Database.GetDbConnection();
                                await connection.OpenAsync();

                                try
                                {
                                    bool hasAccounts = false;

                                    using (var cmd = connection.CreateCommand())
                                    {
                                        cmd.CommandText = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = @table";
                                        var tableParam = cmd.CreateParameter();
                                        tableParam.ParameterName = "@table";
                                        tableParam.Value = "accounts";
                                        cmd.Parameters.Add(tableParam);
                                        var result = await cmd.ExecuteScalarAsync();
                                        hasAccounts = result != null && Convert.ToInt64(result) > 0;
                                    }

                                    if (hasAccounts)
                                    {
                                        logger.LogInformation("Database has existing tables but no migration history. Stamping initial migration...");

                                        var initialMigrationId = pendingMigrations.First();
                                        if (initialMigrationId.Contains("InitialCreate"))
                                        {
                                            using (var cmd = connection.CreateCommand())
                                            {
                                                cmd.CommandText = "CREATE TABLE IF NOT EXISTS \"__EFMigrationsHistory\" (\"MigrationId\" TEXT NOT NULL, \"ProductVersion\" TEXT NOT NULL, CONSTRAINT \"PK___EFMigrationsHistory\" PRIMARY KEY (\"MigrationId\"))";
                                                await cmd.ExecuteNonQueryAsync();
                                            }

                                            using (var cmd = connection.CreateCommand())
                                            {
                                                cmd.CommandText = "INSERT INTO \"__EFMigrationsHistory\" (\"MigrationId\", \"ProductVersion\") VALUES (@migrationId, @productVersion)";
                                                var migrationIdParam = cmd.CreateParameter();
                                                migrationIdParam.ParameterName = "@migrationId";
                                                migrationIdParam.Value = initialMigrationId;
                                                cmd.Parameters.Add(migrationIdParam);
                                                var productVersionParam = cmd.CreateParameter();
                                                productVersionParam.ParameterName = "@productVersion";
                                                productVersionParam.Value = "8.0.4";
                                                cmd.Parameters.Add(productVersionParam);
                                                await cmd.ExecuteNonQueryAsync();
                                            }

                                            logger.LogInformation("Stamped initial migration: {MigrationId}", initialMigrationId);
                                            pendingMigrations = db.Database.GetPendingMigrations().ToList();
                                        }
                                    }
                                }
                                finally
                                {
                                    await connection.CloseAsync();
                                }
                            }
                            catch (Exception stampEx)
                            {
                                logger.LogWarning(stampEx, "Could not check/stamp existing migrations, proceeding with normal migration");
                            }
                        }

                        if (pendingMigrations.Any())
                        {
                            logger.LogInformation("Applying {Count} pending migrations...", pendingMigrations.Count);
                        }
                    }
                }

                db.Database.Migrate();

                var adminUsername = adminBootstrapOptions.Username.Trim();
                var adminPassword = adminBootstrapOptions.Password;
                if (!string.IsNullOrWhiteSpace(adminUsername) || !string.IsNullOrWhiteSpace(adminPassword))
                {
                    if (string.IsNullOrWhiteSpace(adminUsername) || string.IsNullOrWhiteSpace(adminPassword))
                    {
                        throw new InvalidOperationException("AdminBootstrap.Username and AdminBootstrap.Password must both be configured.");
                    }

                    if (!passwordPolicy.Validate(adminPassword, out var passwordError))
                    {
                        throw new InvalidOperationException($"Admin bootstrap password is invalid: {passwordError}");
                    }

                    var existingCredential = await db.PasswordCredentials
                        .AsNoTracking()
                        .FirstOrDefaultAsync(item => item.Username == adminUsername);

                    if (existingCredential == null)
                    {
                        var account = new AccountEntity
                        {
                            Id = Guid.NewGuid(),
                            IsActive = true,
                            CreatedAt = DateTimeOffset.UtcNow,
                            Remark = "Bootstrap admin account"
                        };
                        db.Accounts.Add(account);
                        db.PasswordCredentials.Add(new PasswordCredentialEntity
                        {
                            Id = Guid.NewGuid(),
                            AccountId = account.Id,
                            Username = adminUsername,
                            PasswordHash = passwordHasher.HashPassword(adminPassword),
                            CreatedAt = DateTimeOffset.UtcNow
                        });
                        await db.SaveChangesAsync();
                        logger.LogInformation("Bootstrap admin account created: Username={Username}", adminUsername);
                    }
                    else
                    {
                        logger.LogInformation("Bootstrap admin account already exists: Username={Username}", adminUsername);
                    }
                }

                // Seed app registrations from bootstrap-apps.json file (optional pre-seeding mechanism).
                // The file is mounted by deployment scripts and supports multiple apps.
                // If the file does not exist, skip silently with INFO log (optional pre-seeding).
                var bootstrapAppsFilePath = configuration["BootstrapApps:FilePath"] ?? "/app/data/bootstrap-apps.json";
                if (!string.IsNullOrWhiteSpace(bootstrapAppsFilePath) && File.Exists(bootstrapAppsFilePath))
                {
                    try
                    {
                        var bootstrapJson = await File.ReadAllTextAsync(bootstrapAppsFilePath);
                        var bootstrapApps = System.Text.Json.JsonSerializer.Deserialize<BootstrapAppsOptions>(
                            bootstrapJson,
                            new System.Text.Json.JsonSerializerOptions
                            {
                                PropertyNameCaseInsensitive = true
                            });

                        if (bootstrapApps?.Apps != null)
                        {
                            foreach (var entry in bootstrapApps.Apps)
                            {
                                if (string.IsNullOrWhiteSpace(entry.AppId) || string.IsNullOrWhiteSpace(entry.AppSecret))
                                {
                                    logger.LogWarning("Bootstrap app entry skipped: AppId or AppSecret is empty.");
                                    continue;
                                }

                                var existingApp = await db.AppRegistrations
                                    .AsNoTracking()
                                    .FirstOrDefaultAsync(a => a.AppId == entry.AppId);
                                if (existingApp != null)
                                {
                                    logger.LogInformation("Bootstrap app registration already exists: AppId={AppId}, AppName={AppName}", entry.AppId, entry.AppName);
                                    continue;
                                }

                                db.AppRegistrations.Add(new AppRegistrationEntity
                                {
                                    Id = Guid.NewGuid(),
                                    AppId = entry.AppId,
                                    AppSecretHash = BCrypt.Net.BCrypt.HashPassword(entry.AppSecret),
                                    AppName = entry.AppName,
                                    CallbackUrl = entry.CallbackUrl,
                                    IsActive = true,
                                    CreatedAt = DateTimeOffset.UtcNow
                                });
                                await db.SaveChangesAsync();
                                logger.LogInformation("Bootstrap app registration created: AppId={AppId}, AppName={AppName}", entry.AppId, entry.AppName);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogWarning(ex, "Failed to read or process bootstrap apps file: {FilePath}", bootstrapAppsFilePath);
                    }
                }
                else
                {
                    logger.LogInformation("Bootstrap apps file not found: {FilePath}. Skipping app pre-seeding.", bootstrapAppsFilePath);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Database initialization failed");
                throw;
            }
        }
    }
}
