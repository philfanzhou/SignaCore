using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Validators;
using QuantumZhou.Identity.Host;
using QuantumZhou.Identity.Host.Controllers;

var builder = WebApplication.CreateBuilder(args);

// ========== Serilog (Console + Grafana Loki) ==========
// LOKI_URI 环境变量注入 Loki 地址（覆盖 appsettings.json 中的 fallback）。
// Loki Sink 在 uri 为 null 时会抛 ArgumentNullException，配置文件中提供 fallback uri 确保服务能启动。
// Loki 不可达时 Sink 异步重试，不影响服务运行。
var lokiUri = Environment.GetEnvironmentVariable("LOKI_URI");
if (!string.IsNullOrWhiteSpace(lokiUri))
{
    builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["Serilog:WriteTo:1:Args:uri"] = lokiUri
    });
}
builder.Host.UseAgentSerilog("QuantumZhou.Identity");

var httpPort = builder.Configuration.GetValue<int?>("Endpoints:Http") ?? 5002;

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(httpPort, listenOptions =>
    {
        listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1;
    });
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
});
builder.Services.Configure<Microsoft.Extensions.Hosting.HostOptions>(options =>
{
    options.ShutdownTimeout = TimeSpan.FromSeconds(30);
});

// ========== Infrastructure (DI, gRPC, Auth, CORS, etc.) ==========
var (jwtOptions, dbProvider) = builder.Services.AddIdentityInfrastructure(builder.Configuration, builder.Environment);

var app = builder.Build();

app.Logger.LogInformation("Service endpoints configured: HTTP={HttpPort}", httpPort);
app.Logger.LogInformation("Database: {Provider}", dbProvider);

// ========== HTTPS Warning for Gateway API ==========
// Gateway API transmits AppSecret via request headers; warn if not running behind HTTPS/TLS.
// Note: Kestrel configured via ConfigureKestrel may not populate app.Urls; this is a best-effort check.
var hasHttpsEndpoint = app.Urls.Any(url => url.StartsWith("https://", StringComparison.OrdinalIgnoreCase));
if (!hasHttpsEndpoint)
{
    app.Logger.LogWarning(
        "No HTTPS endpoint detected. Gateway API (X-Admin-AppSecret header) will transmit secrets over plain HTTP. " +
        "In production, enable HTTPS or ensure TLS termination at the reverse proxy.");
}

// ========== 18. Database Initialization (must happen before KeyManager) ==========
var autoMigrate = bool.Parse(builder.Configuration["Database:AutoMigrate"] ?? "true");
if (autoMigrate)
{
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var adminBootstrapOptions = scope.ServiceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AdminBootstrapOptions>>().Value;
        var passwordPolicy = scope.ServiceProvider.GetRequiredService<IPasswordPolicy>();
        var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
        try
            {
                if (!dbProvider.Equals("SQLite", StringComparison.OrdinalIgnoreCase))
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
                                            app.Logger.LogInformation("Reconciled missing column: {Table}.{Column}", table, column);
                                        }
                                        catch (Exception colEx)
                                        {
                                            app.Logger.LogWarning(colEx, "Column {Table}.{Column} may already exist, skipping", table, column);
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
                        app.Logger.LogWarning(reconEx, "Schema reconciliation check skipped");
                    }
                }

            if (!dbProvider.Equals("SQLite", StringComparison.OrdinalIgnoreCase))
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
                                    app.Logger.LogInformation("Database has existing tables but no migration history. Stamping initial migration...");

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

                                        app.Logger.LogInformation("Stamped initial migration: {MigrationId}", initialMigrationId);
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
                            app.Logger.LogWarning(stampEx, "Could not check/stamp existing migrations, proceeding with normal migration");
                        }
                    }

                    if (pendingMigrations.Any())
                    {
                        app.Logger.LogInformation("Applying {Count} pending migrations...", pendingMigrations.Count);
                    }
                }
            }

            if (dbProvider.Equals("SQLite", StringComparison.OrdinalIgnoreCase))
            {
                db.Database.EnsureCreated();
            }
            else
            {
                db.Database.Migrate();
            }

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
                    app.Logger.LogInformation("Bootstrap admin account created: Username={Username}", adminUsername);
                }
                else
                {
                    app.Logger.LogInformation("Bootstrap admin account already exists: Username={Username}", adminUsername);
                }
            }

            // Initialize Teacher Portal app registration from configuration
            var teacherAppId = Environment.GetEnvironmentVariable("TEACHER_PORTAL_APP_ID")
                ?? builder.Configuration["TeacherPortal:AppId"] ?? string.Empty;
            var teacherAppSecret = Environment.GetEnvironmentVariable("TEACHER_PORTAL_APP_SECRET")
                ?? builder.Configuration["TeacherPortal:AppSecret"] ?? string.Empty;
            var teacherCallbackUrl = builder.Configuration["TeacherPortal:CallbackUrl"] ?? "http://localhost:5004/api/auth/callback";

            if (!string.IsNullOrWhiteSpace(teacherAppId) && !string.IsNullOrWhiteSpace(teacherAppSecret))
            {
                var existingTeacherApp = await db.AppRegistrations
                    .AsNoTracking()
                    .FirstOrDefaultAsync(a => a.AppId == teacherAppId);
                if (existingTeacherApp == null)
                {
                    db.AppRegistrations.Add(new AppRegistrationEntity
                    {
                        Id = Guid.NewGuid(),
                        AppId = teacherAppId,
                        AppSecretHash = BCrypt.Net.BCrypt.HashPassword(teacherAppSecret),
                        AppName = "Teacher Portal",
                        CallbackUrl = teacherCallbackUrl,
                        IsActive = true,
                        CreatedAt = DateTimeOffset.UtcNow
                    });
                    await db.SaveChangesAsync();
                    app.Logger.LogInformation("Teacher Portal app registration created: AppId={AppId}", teacherAppId);
                }
                else
                {
                    app.Logger.LogInformation("Teacher Portal app registration already exists: AppId={AppId}", teacherAppId);
                }
            }
            else
            {
                app.Logger.LogWarning("Teacher Portal app registration skipped: AppId/AppSecret not configured. Set TEACHER_PORTAL_APP_ID and TEACHER_PORTAL_APP_SECRET environment variables or TeacherPortal:AppId/TeacherPortal:AppSecret in configuration.");
            }
        }
        catch (Exception ex)
        {
            app.Logger.LogError(ex, "Database initialization failed");
            throw;
        }
    }
}
else
{
    app.Logger.LogWarning("Auto database migration is disabled. Ensure migrations are applied manually before starting the service.");
}

// ========== Wait for KeyManager initialization before accepting requests ==========
var keyManager = app.Services.GetRequiredService<IKeyManager>();
await keyManager.InitializationCompleted;
app.Logger.LogInformation("KeyManager initialization verified");

// ========== Configure JWT Bearer signing key resolver after KeyManager is ready ==========
var jwtBearerOptions = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<JwtBearerOptions>>();
var bearerOptions = jwtBearerOptions.Get(JwtBearerDefaults.AuthenticationScheme);
bearerOptions.TokenValidationParameters.IssuerSigningKeyResolver = (_, _, _, _) =>
{
    var key = keyManager.GetCurrentKey();
    return new SecurityKey[] { key };
};

// ========== 19. Health Check Endpoint ==========
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Identity Service API v1"));
}
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseCors("AdminWeb");
app.UseAuthentication();

// ========== Sensitive Header Redaction Middleware ==========
// Strips X-Admin-AppSecret from the request headers after authentication
// so that downstream logging/middleware cannot accidentally log the secret value.
// The secret has already been consumed by GatewayController.ValidateGatewayRequestAsync.
app.Use(async (context, next) =>
{
    if (context.Request.Headers.TryGetValue(GatewayController.AppSecretHeader, out var secretValue))
    {
        // Store the secret in HttpContext.Items for controller access, then remove from headers
        context.Items[GatewayController.AppSecretHeader] = secretValue.ToString();
        context.Request.Headers.Remove(GatewayController.AppSecretHeader);
    }
    await next();
});

app.UseAuthorization();
app.UseRateLimiter();

app.MapHealthChecks("/health");

// ========== JWKS Rate Limiting ==========
var jwksRateLimiter = new System.Threading.RateLimiting.FixedWindowRateLimiter(
    new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
    {
        PermitLimit = 60,
        Window = TimeSpan.FromSeconds(60),
        QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
        QueueLimit = 0
    });

var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    app.Logger.LogInformation("Application is shutting down...");
    jwksRateLimiter.Dispose();
});

app.Use(async (context, next) =>
{
    if (context.Request.Path == "/.well-known/jwks")
    {
        var lease = await jwksRateLimiter.AcquireAsync(permitCount: 1, context.RequestAborted);
        if (!lease.IsAcquired)
        {
            app.Logger.LogWarning(
                "JWKS rate limit exceeded: ClientIp={ClientIp}, Limit=60/60s",
                context.Connection.RemoteIpAddress);
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            await context.Response.WriteAsync("Too many requests to JWKS endpoint. Please try again later.");
            return;
        }
        try
        {
            await next(context);
        }
        finally
        {
            lease.Dispose();
        }
    }
    else
    {
        await next(context);
    }
});

// ========== OIDC Discovery ==========
app.MapGet("/.well-known/openid-configuration", (HttpContext httpContext, IConfiguration configuration) =>
{
    var httpPort = configuration.GetValue("Endpoints:Http", 5002);
    var host = httpContext.Request.Host.Host;
    var scheme = httpContext.Request.Scheme;
    var baseUrl = $"{scheme}://{host}:{httpPort}";

    return Results.Ok(new
    {
        issuer = "QuantumZhou.Identity",
        jwks_uri = $"{baseUrl}/.well-known/jwks",
        token_endpoint = $"{baseUrl}/api/auth/token",
        response_types_supported = new[] { "token" },
        subject_types_supported = new[] { "public" },
        id_token_signing_alg_values_supported = new[] { "RS256" },
        claims_supported = new[] { "sub", "name", "role", "auth_method", "nickname" }
    });
});

// ========== JWKS Discovery ==========
app.MapGet("/.well-known/jwks", async (IKeyManager keyManager) =>
{
    var keys = await keyManager.GetValidKeysAsync();
    var jwks = keys.Select(key =>
    {
        var rsa = key.Rsa ?? throw new InvalidOperationException("Key is not RSA");
        var parameters = rsa.ExportParameters(false);
        return new
        {
            kty = "RSA",
            use = "sig",
            kid = key.KeyId,
            alg = "RS256",
            n = Base64UrlEncoder.Encode(parameters.Modulus!),
            e = Base64UrlEncoder.Encode(parameters.Exponent!)
        };
    });
    return Results.Ok(new { keys = jwks });
});

app.MapControllers();

// ========== Prometheus Metrics Endpoint ==========
app.MapPrometheusScrapingEndpoint();

// ========== Static files & SPA for Admin Web (HTTP port only) ==========
var appTitle = builder.Configuration["APP_TITLE"] ?? "QuantumZhou.Identity";
app.MapWhen(context =>
    context.Connection.LocalPort == httpPort &&
    !context.Request.Path.StartsWithSegments("/api") &&
    !context.Request.Path.StartsWithSegments("/.well-known") &&
    !context.Request.Path.StartsWithSegments("/health") &&
    !context.Request.Path.StartsWithSegments("/metrics"),
    adminApp =>
    {
        adminApp.UseDefaultFiles();

        // Inject app title from APP_TITLE env var into index.html at runtime
        adminApp.Use(async (context, next) =>
        {
            if (context.Request.Path == "/index.html")
            {
                var wwwroot = app.Environment.WebRootPath;
                var filePath = Path.Combine(wwwroot, "index.html");
                if (File.Exists(filePath))
                {
                    var content = await File.ReadAllTextAsync(filePath);
                    content = content.Replace("__APP_TITLE__", appTitle);
                    // Inject global variable for Vue app to read at runtime
                    content = content.Replace("</head>", $"<script>window.__APP_TITLE__ = '{appTitle.Replace("'", "\\'")}';</script></head>");
                    context.Response.ContentType = "text/html; charset=utf-8";
                    await context.Response.WriteAsync(content);
                    return;
                }
            }
            await next();
        });

        adminApp.UseStaticFiles();

        // SPA fallback for Vue Router history mode
        adminApp.MapWhen(_ => true, spaApp =>
        {
            spaApp.Use(async (context, next) =>
            {
                context.Request.Path = "/index.html";
                await next();
            });
            spaApp.UseStaticFiles();
        });
    });

app.Run();

public partial class Program { }
