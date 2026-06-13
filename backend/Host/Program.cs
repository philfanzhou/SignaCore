using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Validators;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Domain.Services.WeChat;
using QuantumZhou.Identity.Host;
using QuantumZhou.Identity.Service;

var builder = WebApplication.CreateBuilder(args);

var grpcPort = builder.Configuration.GetValue<int?>("Endpoints:Grpc") ?? 5001;
var httpPort = builder.Configuration.GetValue<int?>("Endpoints:Http") ?? 5002;

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(grpcPort, listenOptions =>
    {
        listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http2;
    });
    options.ListenAnyIP(httpPort, listenOptions =>
    {
        listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1AndHttp2;
    });
});

// ========== OpenTelemetry & Metrics ==========
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics.AddAspNetCoreInstrumentation()
               .AddRuntimeInstrumentation()
               .AddPrometheusExporter();
    })
    .WithTracing(tracing =>
    {
        tracing.AddAspNetCoreInstrumentation()
               .AddHttpClientInstrumentation()
               .AddSource("QuantumZhou.Identity");
    });

// ========== 1. Database ==========
var dbProvider = builder.Configuration["Database:Provider"] ?? "SQLite";
var connectionString = dbProvider.Equals("PostgreSQL", StringComparison.OrdinalIgnoreCase)
    ? builder.Configuration.GetConnectionString("PostgreSQL") 
        ?? "Host=localhost;Port=5432;Database=quantumzhou_identity;Username=postgres"
    : builder.Configuration.GetConnectionString("Default") 
        ?? "Data Source=quantumzhou_identity.db";

// Add password for PostgreSQL if available via environment variable
if (dbProvider.Equals("PostgreSQL", StringComparison.OrdinalIgnoreCase))
{
    var dbPassword = Environment.GetEnvironmentVariable("DB_PASSWORD");
    if (dbPassword != null && !connectionString.Contains("Password="))
    {
        connectionString = $"{connectionString};Password={dbPassword}";
    }
}

builder.Services.AddDbContext<IdentityDbContext>(options =>
{
    if (dbProvider.Equals("PostgreSQL", StringComparison.OrdinalIgnoreCase))
    {
        options.UseNpgsql(connectionString, npgsqlOptions =>
        {
            npgsqlOptions.EnableRetryOnFailure(
                maxRetryCount: 3,
                maxRetryDelay: TimeSpan.FromSeconds(4),
                errorCodesToAdd: null);
        });
    }
    else
    {
        options.UseSqlite(connectionString);
    }
});

// ========== 2. HttpClient for Callback ==========
builder.Services.AddHttpClient("Callback");

// ========== 3. RSA Key Manager ==========
builder.Services.AddSingleton<IKeyManager, KeyManager>();

// ========== 4. JWT Options ==========
var jwtOptions = new JwtOptions
{
    Issuer = builder.Configuration["Jwt:Issuer"] ?? "QuantumZhou.Identity",
    Audience = builder.Configuration["Jwt:Audience"] ?? "QuantumZhou.microservices",
    TokenExpirationHours = int.Parse(builder.Configuration["Jwt:TokenExpirationHours"] ?? "2")
};
jwtOptions.Validate();
builder.Services.AddSingleton(jwtOptions);

// ========== 5. Token Service ==========
builder.Services.AddSingleton<ITokenService, JwtTokenService>();

// ========== 6. Password Hasher ==========
builder.Services.AddSingleton(new PasswordHasherOptions
{
    WorkFactor = int.Parse(builder.Configuration["PasswordHasher:WorkFactor"] ?? "11")
});
builder.Services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();

// ========== 6. Refresh Token Options ==========
var refreshTokenOptions = new RefreshTokenOptions
{
    RefreshTokenExpirationDays = int.Parse(builder.Configuration["RefreshToken:ExpirationDays"] ?? "7")
};
refreshTokenOptions.Validate();
builder.Services.AddSingleton(refreshTokenOptions);

// ========== 7. Claims Resolver ==========
builder.Services.AddScoped<ClaimsResolver>();

// ========== 8. Callback Service ==========
var callbackAllowedDomains = builder.Configuration.GetSection("Callback:AllowedDomains").Get<string[]>() ?? [];
var callbackAllowPrivate = builder.Configuration.GetValue<bool>("Callback:AllowPrivateAddresses");
builder.Services.AddSingleton(new CallbackUrlValidator(callbackAllowedDomains, callbackAllowPrivate));
builder.Services.AddScoped<ICallbackService, CallbackService>();

// ========== 9. SMS OTP Services ==========
var smsOptions = new SmsOptions
{
    OtpTtlSeconds = int.Parse(builder.Configuration["Sms:OtpTtlSeconds"] ?? "300"),
    MaxAttempts = int.Parse(builder.Configuration["Sms:MaxAttempts"] ?? "5"),
    LockoutSeconds = int.Parse(builder.Configuration["Sms:LockoutSeconds"] ?? "600")
};
builder.Services.AddSingleton(smsOptions);
if (!string.IsNullOrWhiteSpace(connectionString))
{
    builder.Services.AddScoped<IOtpService, DbOtpService>();
}
else
{
    builder.Services.AddSingleton<IOtpService, InMemoryOtpService>();
}
builder.Services.AddSingleton<ISmsSender, LoggingSmsSender>();

// ========== 11. WeChat API Client ==========
var wechatOptions = new WechatOptions
{
    AppId = builder.Configuration["WeChat:AppId"] ?? string.Empty,
    AppSecret = builder.Configuration["WeChat:AppSecret"] ?? string.Empty,
    ApiBaseUrl = builder.Configuration["WeChat:ApiBaseUrl"] ?? "https://api.weixin.qq.com"
};
builder.Services.AddSingleton(wechatOptions);
builder.Services.AddHttpClient<IWechatApiClient, WechatApiClient>(client =>
{
    client.BaseAddress = new Uri(wechatOptions.ApiBaseUrl);
    client.Timeout = TimeSpan.FromSeconds(10);
});

// ========== 12. Repository Layer ==========
builder.Services.AddScoped<IAccountRepository, AccountRepository>();
builder.Services.AddScoped<IPasswordCredentialRepository, PasswordCredentialRepository>();
builder.Services.AddScoped<IUserLoginRepository, UserLoginRepository>();
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddScoped<IAppRegistrationRepository, AppRegistrationRepository>();
builder.Services.AddScoped<ISecurityKeyRepository, SecurityKeyRepository>();
builder.Services.AddScoped<IOtpRepository, OtpRepository>();
builder.Services.AddScoped<ILoginAttemptRepository, LoginAttemptRepository>();
builder.Services.AddScoped<ILoginHistoryRepository, LoginHistoryRepository>();
builder.Services.AddScoped<IAuditLogRepository, AuditLogRepository>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<IUnitOfWork, EfCoreUnitOfWork>();

// ========== 12.5. Gateway Validation Service ==========
builder.Services.AddScoped<GatewayValidationService>();

// ========== 12.5. Password Policy ==========
builder.Services.AddSingleton<IPasswordPolicy, DefaultPasswordPolicy>();

// ========== 13. Rate Limiting Options ==========
var rateLimitingOptions = new RateLimitingOptions
{
    PermitLimitPerClient = int.Parse(builder.Configuration["RateLimiting:PermitLimitPerClient"] ?? "20"),
    WindowSeconds = int.Parse(builder.Configuration["RateLimiting:WindowSeconds"] ?? "60"),
    CleanupIntervalSeconds = int.Parse(builder.Configuration["RateLimiting:CleanupIntervalSeconds"] ?? "300")
};
builder.Services.AddSingleton(rateLimitingOptions);
builder.Services.AddSingleton<RateLimitingInterceptor>();

// ========== 14. Validators (Auto-registered) ==========
builder.Services.AddScoped<IIdentityValidator, PasswordValidator>();
builder.Services.AddScoped<IIdentityValidator, SmsValidator>();
builder.Services.AddScoped<IIdentityValidator, WechatValidator>();
builder.Services.AddScoped<IIdentityValidator, RefreshTokenValidator>();

// ========== 14. Validator Factory (auto-builds dictionary from injected validators) ==========
builder.Services.AddScoped<ValidatorFactory>();

// ========== 15. Background Cleanup Service ==========
builder.Services.AddHostedService<CleanupWorker>();

// ========== 16. gRPC ==========
builder.Services.AddGrpc(options =>
{
    options.Interceptors.Add<CorrelationIdInterceptor>();
    options.Interceptors.Add<RateLimitingInterceptor>();
    options.Interceptors.Add<ExceptionHandlingInterceptor>();
    options.MaxReceiveMessageSize = int.Parse(builder.Configuration["Grpc:MaxReceiveMessageSize"] ?? "4194304");
    options.MaxSendMessageSize = int.Parse(builder.Configuration["Grpc:MaxSendMessageSize"] ?? "4194304");
});

// ========== 16. Health Checks ==========
builder.Services.AddHealthChecks()
    .AddDbContextCheck<IdentityDbContext>("database");

var adminWebOrigins = builder.Configuration.GetSection("AdminWeb:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
builder.Services.Configure<AdminWebOptions>(builder.Configuration.GetSection(AdminWebOptions.SectionName));
builder.Services.Configure<AdminBootstrapOptions>(builder.Configuration.GetSection(AdminBootstrapOptions.SectionName));
builder.Services.AddCors(options =>
{
    options.AddPolicy("AdminWeb", policy =>
    {
        if (adminWebOrigins.Length == 0)
        {
            policy.AllowAnyOrigin()
                .AllowAnyHeader()
                .AllowAnyMethod();
            return;
        }

        policy.WithOrigins(adminWebOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "qz_admin_session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromHours(12);
        options.Events = new CookieAuthenticationEvents
        {
            OnRedirectToLogin = context =>
            {
                if (context.Request.Path.StartsWithSegments("/api/admin"))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                }

                context.Response.Redirect(context.RedirectUri);
                return Task.CompletedTask;
            },
            OnRedirectToAccessDenied = context =>
            {
                if (context.Request.Path.StartsWithSegments("/api/admin"))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                }

                context.Response.Redirect(context.RedirectUri);
                return Task.CompletedTask;
            }
        };
    })
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("AdminSession", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("admin_access", "true");
    })
    .AddPolicy("UserProfile", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Identity Service API", Version = "v1" });
});

builder.Services.AddControllers();

// ========== 18. Auth Service ==========
builder.Services.AddScoped<AuthServiceImpl>();

// ========== 18. Auth Metrics ==========
builder.Services.AddSingleton<AuthMetrics>();

var app = builder.Build();

var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    app.Logger.LogInformation("Application is shutting down...");
});


app.Logger.LogInformation("Service endpoints configured: gRPC={GrpcPort}, HTTP={HttpPort}", grpcPort, httpPort);

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
                                    cmd.CommandText = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = 'accounts'";
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
                                            cmd.CommandText = $"INSERT INTO \"__EFMigrationsHistory\" (\"MigrationId\", \"ProductVersion\") VALUES ('{initialMigrationId}', '8.0.4')";
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

            // Initialize Teacher Portal app registration for testing purposes
            var teacherAppId = "a6eab9bd87404c0ababc910114d11a62";
            var teacherAppSecret = "cGzoAwXaP+PahtD3qXYVY75IJiPWtfbt/4SIt+WrKoQ=";
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
                    CallbackUrl = "http://localhost:5004/api/auth/callback",
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
app.UseCors("AdminWeb");
app.UseAuthentication();
app.UseAuthorization();

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

app.Use(async (context, next) =>
{
    if (context.Request.Path == "/.well-known/jwks")
    {
        var lease = await jwksRateLimiter.AcquireAsync(permitCount: 1, context.RequestAborted);
        if (!lease.IsAcquired)
        {
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
app.MapGet("/.well-known/jwks", (IKeyManager keyManager) =>
{
    var key = keyManager.GetCurrentKey();
    var rsa = key.Rsa ?? throw new InvalidOperationException("Key is not RSA");
    var parameters = rsa.ExportParameters(false);

    var jwk = new
    {
        kty = "RSA",
        use = "sig",
        kid = key.KeyId,
        alg = "RS256",
        n = Base64UrlEncoder.Encode(parameters.Modulus!),
        e = Base64UrlEncoder.Encode(parameters.Exponent!)
    };

    return Results.Ok(new { keys = new[] { jwk } });
});

app.MapGrpcService<AuthServiceImpl>();

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
