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
using QuantumZhou.Identity.Domain.Keys;
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
        // ---- OpenTelemetry & Metrics ----
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

        // ---- Database ----
        var databaseOptions = BindDatabaseOptions(configuration);
        services.AddSingleton(databaseOptions);

        services.AddDbContext<IdentityDbContext>(options =>
        {
            options.UseIdentityDatabase(databaseOptions);
        });

        // ---- HttpClient for Callback ----
        services.AddHttpClient("Callback");

        // ---- RSA Key Manager ----
        // 主密钥来源与私钥加解密是两个独立关注点，KeyManager 只负责密钥生命周期编排。
        services.AddSingleton<IMasterKeyProvider, FileMasterKeyProvider>();
        services.AddSingleton<IPrivateKeyProtector, AesGcmPrivateKeyProtector>();
        services.AddSingleton<IKeyManager, KeyManager>();

        // ---- JWT Options ----
        var jwtOptions = services.RegisterSingleton(new JwtOptions
        {
            Issuer = configuration["Jwt:Issuer"] ?? "QuantumZhou.Identity",
            Audience = configuration["Jwt:Audience"] ?? "QuantumZhou.microservices",
            TokenExpirationHours = int.Parse(configuration["Jwt:TokenExpirationHours"] ?? "2")
        });
        jwtOptions.Validate();

        // ---- Token Service ----
        services.AddSingleton<ITokenService, JwtTokenService>();

        // ---- Password Hasher ----
        services.RegisterSingleton(new PasswordHasherOptions
        {
            WorkFactor = configuration.GetValue(
                "PasswordHasher:WorkFactor",
                IdentityConstants.BCryptWorkFactor)
        });
        services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();

        // ---- Refresh Token Options ----
        var refreshTokenOptions = services.RegisterSingleton(new RefreshTokenOptions
        {
            RefreshTokenExpirationDays = int.Parse(configuration["RefreshToken:ExpirationDays"] ?? "7")
        });
        refreshTokenOptions.Validate();

        // ---- Claims Resolver ----
        services.AddScoped<ClaimsResolver>();

        // ---- Callback Service ----
        var callbackAllowedDomains = configuration.GetSection("Callback:AllowedDomains").Get<string[]>() ?? [];
        // 默认允许私有地址：微服务回调走内网是常态。公网部署可显式设为 false 拒绝解析到内网的回调 URL。
        var callbackAllowPrivateAddresses = configuration.GetValue("Callback:AllowPrivateAddresses", true);
        services.AddSingleton(new CallbackUrlValidator(callbackAllowedDomains, callbackAllowPrivateAddresses));
        services.AddScoped<ICallbackService, CallbackService>();

        // ---- SMS OTP Services ----
        var smsOptions = services.RegisterSingleton(new SmsOptions
        {
            OtpTtlSeconds = int.Parse(configuration["Sms:OtpTtlSeconds"] ?? "300"),
            MaxAttempts = int.Parse(configuration["Sms:MaxAttempts"] ?? "5"),
            LockoutSeconds = int.Parse(configuration["Sms:LockoutSeconds"] ?? "600"),
            BypassCode = configuration["Sms:BypassCode"] ?? Environment.GetEnvironmentVariable("SMS_BYPASS_CODE"),
            BypassPhones = ResolveBypassPhones(configuration)
        });
        services.AddScoped<IOtpService, DbOtpService>();
        // 开发环境使用 LoggingSmsSender，生产环境使用 ThrowingSmsSender 防止验证码泄露
        if (environment.IsDevelopment())
        {
            services.AddSingleton<ISmsSender, LoggingSmsSender>();
        }
        else
        {
            services.AddSingleton<ISmsSender, ThrowingSmsSender>();
        }

        // ---- WeChat API Client ----
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

        // ---- Repository Layer ----
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

        // ---- Gateway Validation Service ----
        services.AddScoped<GatewayValidationService>();

        // ---- User Query Service ----
        services.AddScoped<IUserQueryService, UserQueryService>();

        // ---- Refresh Token Service ----
        services.AddScoped<IRefreshTokenService, RefreshTokenService>();
        services.AddScoped<IAccountLoginInfoService, AccountLoginInfoService>();

        // ---- Password Policy ----
        services.AddSingleton<IPasswordPolicy, DefaultPasswordPolicy>();

        // ---- Rate Limiting (ASP.NET Core built-in) ----
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

        // ---- Validators (Auto-registered) ----
        services.AddScoped<IIdentityValidator, PasswordValidator>();
        services.AddScoped<IIdentityValidator, SmsValidator>();
        services.AddScoped<IIdentityValidator, WechatValidator>();
        services.AddScoped<IIdentityValidator, RefreshTokenValidator>();

        // ---- Validator Factory (auto-builds dictionary from injected validators) ----
        services.AddScoped<ValidatorFactory>();

        // ---- Background Cleanup Service ----
        services.AddHostedService<CleanupWorker>();

        // ---- Health Checks ----
        services.AddHealthChecks()
            .AddDbContextCheck<IdentityDbContext>("database");

        var adminWebOrigins = configuration.GetSection("AdminWeb:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
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

        // ---- Auth Metrics ----
        services.AddSingleton<AuthMetrics>();

        return (jwtOptions, databaseOptions.Provider);
    }

    private static T RegisterSingleton<T>(this IServiceCollection services, T options) where T : class
    {
        services.AddSingleton(options);
        return options;
    }

    /// <summary>
    /// 解析短信绕过白名单。Consul KV 里写 JSON 数组，环境变量里写逗号分隔字符串，两种都支持。
    /// 未配置时返回空列表——此时即使配了 BypassCode，<c>SmsValidator</c> 也不会放行任何号码。
    /// </summary>
    internal static IReadOnlyList<string> ResolveBypassPhones(IConfiguration configuration)
    {
        var section = configuration.GetSection("Sms:BypassPhones");

        var rawValues = section.GetChildren().Any()
            ? section.Get<string[]>() ?? []
            : (section.Value ?? Environment.GetEnvironmentVariable("SMS_BYPASS_PHONES") ?? string.Empty)
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return rawValues
            .Select(static phone => phone.Trim())
            .Where(static phone => phone.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    internal static DatabaseOptions BindDatabaseOptions(IConfiguration configuration)
    {
        var legacyKeys = new[]
        {
            "Database:Name",
            "ConnectionStrings:Default",
            "ConnectionStrings:PostgreSQL"
        };

        var configuredLegacyKeys = legacyKeys
            .Where(key => configuration[key] is not null)
            .ToList();

        if (configuration.GetSection("PostgreSql").GetChildren().Any())
        {
            configuredLegacyKeys.Add("PostgreSql:*");
        }

        if (configuredLegacyKeys.Count > 0)
        {
            throw new InvalidOperationException(
                $"Legacy database configuration is not supported: {string.Join(", ", configuredLegacyKeys)}.");
        }

        var options = configuration
            .GetRequiredSection(DatabaseOptions.SectionName)
            .Get<DatabaseOptions>()
            ?? throw new InvalidOperationException("Database configuration is required.");

        options.Validate();
        return options;
    }
}
