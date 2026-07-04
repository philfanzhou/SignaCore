using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Domain.Services.WeChat;
using QuantumZhou.Identity.Domain.Validators;

namespace QuantumZhou.Identity.Host;

public static class ServiceCollectionExtensions
{
    public static (JwtOptions JwtOptions, string DbProvider) AddIdentityInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        // ========== OpenTelemetry & Metrics ==========
        services.AddOpenTelemetry()
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
                var otlpEndpoint = configuration["OpenTelemetry:OtlpEndpoint"];
                if (!string.IsNullOrWhiteSpace(otlpEndpoint))
                {
                    tracing.AddOtlpExporter(options =>
                    {
                        options.Endpoint = new Uri(otlpEndpoint);
                    });
                }
            });

        // ========== 1. Database ==========
        var dbProvider = configuration["Database:Provider"] ?? "SQLite";
        var connectionString = dbProvider.Equals("PostgreSQL", StringComparison.OrdinalIgnoreCase)
            ? configuration.GetConnectionString("PostgreSQL")
                ?? "Host=localhost;Port=5432;Database=quantumzhou_identity;Username=postgres"
            : configuration.GetConnectionString("Default")
                ?? "Data Source=quantumzhou_identity.db";

        // Add password for PostgreSQL if available via environment variable
        if (dbProvider.Equals("PostgreSQL", StringComparison.OrdinalIgnoreCase))
        {
            var dbPassword = Environment.GetEnvironmentVariable("DB_PASSWORD");
            if (dbPassword != null && !connectionString.Contains("Password="))
            {
                connectionString = $"{connectionString};Password={dbPassword}";
            }
            // 添加连接池配置
            if (!connectionString.Contains("Pooling=", StringComparison.OrdinalIgnoreCase))
            {
                connectionString = $"{connectionString};Pooling=true;Minimum Pool Size=5;Maximum Pool Size=100;Connection Lifetime=300";
            }
        }

        services.AddDbContext<IdentityDbContext>(options =>
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
        services.AddHttpClient("Callback");

        // ========== 3. RSA Key Manager ==========
        services.AddSingleton<IKeyManager, KeyManager>();

        // ========== 4. JWT Options ==========
        var jwtOptions = services.RegisterSingleton(new JwtOptions
        {
            Issuer = configuration["Jwt:Issuer"] ?? "QuantumZhou.Identity",
            Audience = configuration["Jwt:Audience"] ?? "QuantumZhou.microservices",
            TokenExpirationHours = int.Parse(configuration["Jwt:TokenExpirationHours"] ?? "2")
        });
        jwtOptions.Validate();

        // ========== 5. Token Service ==========
        services.AddSingleton<ITokenService, JwtTokenService>();

        // ========== 6. Password Hasher ==========
        services.RegisterSingleton(new PasswordHasherOptions
        {
            WorkFactor = int.Parse(configuration["PasswordHasher:WorkFactor"] ?? "11")
        });
        services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();

        // ========== 6. Refresh Token Options ==========
        var refreshTokenOptions = services.RegisterSingleton(new RefreshTokenOptions
        {
            RefreshTokenExpirationDays = int.Parse(configuration["RefreshToken:ExpirationDays"] ?? "7")
        });
        refreshTokenOptions.Validate();

        // ========== 7. Claims Resolver ==========
        services.AddScoped<ClaimsResolver>();

        // ========== 8. Callback Service ==========
        var callbackAllowedDomains = configuration.GetSection("Callback:AllowedDomains").Get<string[]>() ?? [];
        services.AddSingleton(new CallbackUrlValidator(callbackAllowedDomains));
        services.AddScoped<ICallbackService, CallbackService>();

        // ========== 9. SMS OTP Services ==========
        var smsOptions = services.RegisterSingleton(new SmsOptions
        {
            OtpTtlSeconds = int.Parse(configuration["Sms:OtpTtlSeconds"] ?? "300"),
            MaxAttempts = int.Parse(configuration["Sms:MaxAttempts"] ?? "5"),
            LockoutSeconds = int.Parse(configuration["Sms:LockoutSeconds"] ?? "600"),
            BypassCode = configuration["Sms:BypassCode"] ?? Environment.GetEnvironmentVariable("SMS_BYPASS_CODE")
        });
        if (dbProvider.Equals("PostgreSQL", StringComparison.OrdinalIgnoreCase))
        {
            services.AddScoped<IOtpService, DbOtpService>();
        }
        else
        {
            services.AddSingleton<IOtpService, InMemoryOtpService>();
        }
        // 开发环境使用 LoggingSmsSender，生产环境使用 ThrowingSmsSender 防止验证码泄露
        if (environment.IsDevelopment())
        {
            services.AddSingleton<ISmsSender, LoggingSmsSender>();
        }
        else
        {
            services.AddSingleton<ISmsSender, ThrowingSmsSender>();
        }

        // ========== 11. WeChat API Client ==========
        var wechatOptions = services.RegisterSingleton(new WechatOptions
        {
            AppId = configuration["WeChat:AppId"] ?? string.Empty,
            AppSecret = configuration["WeChat:AppSecret"] ?? string.Empty,
            ApiBaseUrl = configuration["WeChat:ApiBaseUrl"] ?? "https://api.weixin.qq.com"
        });
        services.AddHttpClient<IWechatApiClient, WechatApiClient>(client =>
        {
            client.BaseAddress = new Uri(wechatOptions.ApiBaseUrl);
            client.Timeout = TimeSpan.FromSeconds(10);
        });

        // ========== 12. Repository Layer ==========
        services.AddScoped<IAccountRepository, AccountRepository>();
        services.AddScoped<IPasswordCredentialRepository, PasswordCredentialRepository>();
        services.AddScoped<IUserLoginRepository, UserLoginRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IAppRegistrationRepository, AppRegistrationRepository>();
        services.AddScoped<ISecurityKeyRepository, SecurityKeyRepository>();
        services.AddScoped<IOtpRepository, OtpRepository>();
        services.AddScoped<ILoginAttemptRepository, LoginAttemptRepository>();
        services.AddScoped<ILoginHistoryRepository, LoginHistoryRepository>();
        services.AddScoped<IAuditLogRepository, AuditLogRepository>();
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IUnitOfWork, EfCoreUnitOfWork>();

        // ========== 12.5. Gateway Validation Service ==========
        services.AddScoped<GatewayValidationService>();

        // ========== 12.6. User Query Service ==========
        services.AddScoped<IUserQueryService, UserQueryService>();

        // ========== 12.7. Refresh Token Service ==========
        services.AddScoped<IRefreshTokenService, RefreshTokenService>();
        services.AddScoped<IAccountLoginInfoService, AccountLoginInfoService>();

        // ========== 12.5. Password Policy ==========
        services.AddSingleton<IPasswordPolicy, DefaultPasswordPolicy>();

        // ========== 13. Rate Limiting (ASP.NET Core built-in) ==========
        // Per-IP fixed window limiter: 100 requests per 60 seconds per client IP.
        // /health, /metrics, /.well-known/jwks are exempt (have their own limits or are infra).
        services.AddRateLimiter(options =>
        {
            options.AddFixedWindowLimiter("default", opt =>
            {
                opt.AutoReplenishment = true;
                opt.PermitLimit = 100;
                opt.Window = TimeSpan.FromSeconds(60);
            });
            options.GlobalLimiter = System.Threading.RateLimiting.PartitionedRateLimiter.Create<
                Microsoft.AspNetCore.Http.HttpContext,
                System.Net.IPAddress>(httpContext =>
            {
                var path = httpContext.Request.Path.Value ?? string.Empty;
                // Exempt infrastructure endpoints from global rate limiting
                if (path == "/health" || path == "/metrics" || path == "/.well-known/jwks")
                {
                    return System.Threading.RateLimiting.RateLimitPartition.GetNoLimiter(
                        System.Net.IPAddress.Loopback);
                }

                var remoteIp = httpContext.Connection.RemoteIpAddress ?? System.Net.IPAddress.Loopback;
                return System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
                    remoteIp,
                    _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
                    {
                        AutoReplenishment = true,
                        PermitLimit = 100,
                        Window = TimeSpan.FromSeconds(60)
                    });
            });
            options.OnRejected = async (context, _) =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.HttpContext.Response.ContentType = "application/json";
                await context.HttpContext.Response.WriteAsync(
                    """{"status":429,"title":"Too Many Requests","detail":"Rate limit exceeded. Please try again later."}""");
            };
        });

        // ========== 14. Validators (Auto-registered) ==========
        services.AddScoped<IIdentityValidator, PasswordValidator>();
        services.AddScoped<IIdentityValidator, SmsValidator>();
        services.AddScoped<IIdentityValidator, WechatValidator>();
        services.AddScoped<IIdentityValidator, RefreshTokenValidator>();

        // ========== 14. Validator Factory (auto-builds dictionary from injected validators) ==========
        services.AddScoped<ValidatorFactory>();

        // ========== 15. Background Cleanup Service ==========
        services.AddHostedService<CleanupWorker>();

        // ========== 16. Health Checks ==========
        services.AddHealthChecks()
            .AddDbContextCheck<IdentityDbContext>("database");

        var adminWebOrigins = configuration.GetSection("AdminWeb:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
        services.Configure<AdminWebOptions>(configuration.GetSection(AdminWebOptions.SectionName));
        services.Configure<AdminBootstrapOptions>(configuration.GetSection(AdminBootstrapOptions.SectionName));
        services.PostConfigure<AdminBootstrapOptions>(options =>
        {
            var envUsername = Environment.GetEnvironmentVariable("ADMIN_BOOTSTRAP_USERNAME");
            if (!string.IsNullOrWhiteSpace(envUsername)) options.Username = envUsername;
            var envPassword = Environment.GetEnvironmentVariable("ADMIN_BOOTSTRAP_PASSWORD");
            if (!string.IsNullOrWhiteSpace(envPassword)) options.Password = envPassword;
        });
        services.AddCors(options =>
        {
            options.AddPolicy("AdminWeb", policy =>
            {
                string[] origins;
                if (adminWebOrigins.Length == 0)
                {
                    if (environment.IsDevelopment())
                    {
                        origins = new[] { "http://localhost:5002", "http://localhost:5003", "http://localhost:5173" };
                    }
                    else
                    {
                        // 生产环境必须显式配置 AdminWeb:AllowedOrigins，否则不启用 CORS
                        origins = Array.Empty<string>();
                    }
                }
                else
                {
                    origins = adminWebOrigins;
                }

                if (origins.Length > 0)
                {
                    policy.WithOrigins(origins)
                        .AllowAnyHeader()
                        .AllowAnyMethod()
                        .AllowCredentials();
                }
                else
                {
                    // 无来源时仅允许基本请求，不携带凭据
                    policy.AllowAnyHeader()
                        .AllowAnyMethod();
                }
            });
        });

        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
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
        services.AddAuthorizationBuilder()
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

        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new() { Title = "Identity Service API", Version = "v1" });
        });

        services.AddControllers();

        // ========== 18. Auth Metrics ==========
        services.AddSingleton<AuthMetrics>();

        return (jwtOptions, dbProvider);
    }

    private static T RegisterSingleton<T>(this IServiceCollection services, T options) where T : class
    {
        services.AddSingleton(options);
        return options;
    }
}
