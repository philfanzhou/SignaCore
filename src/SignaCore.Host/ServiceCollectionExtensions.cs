using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Ldap;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Services.WeChat;
using SignaCore.Domain.Validators;
using SignaCore.Host.Configuration;
using SignaCore.Host.HealthChecks;
using SignaCore.Host.Http;
using SignaCore.Host.Security;
using SignaCore.Host.Services;

namespace SignaCore.Host;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Composes the normal application phase. It runs only after the installation state has been
    /// determined and a valid configuration snapshot has been loaded, so every option bound here is
    /// backed by the database rather than by deployment-provided application settings.
    /// </summary>
    /// <param name="databaseOptions">
    /// From the protected bootstrap file. The connection cannot be read from the database it is
    /// needed to open, so it is the one piece of application configuration that stays outside.
    /// </param>
    /// <param name="masterKeyProvider">
    /// Built in the bootstrap phase from the external root secret, and shared with it so migrations,
    /// settings decryption, and RSA key protection all derive from the same root.
    /// </param>
    internal static (JwtOptions JwtOptions, string DbProvider) AddIdentityInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment,
        DatabaseOptions databaseOptions,
        IMasterKeyProvider masterKeyProvider)
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
                       .AddSource("SignaCore");
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
        services.AddSingleton(databaseOptions);

        services.AddDbContext<IdentityDbContext>(options =>
        {
            options.UseIdentityDatabase(databaseOptions);
        });

        // ---- RSA Key Manager ----
        // Where the master key comes from and how private keys are encrypted are two separate
        // concerns; KeyManager only orchestrates the key lifecycle.
        services.AddSingleton(masterKeyProvider);
        services.AddSingleton<IPrivateKeyProtector, AesGcmPrivateKeyProtector>();
        services.AddSingleton<IConfigurationProtector, AesGcmConfigurationProtector>();
        services.AddSingleton<IKeyManager, KeyManager>();

        // Administrative cookies must survive process restarts and be readable by every replica.
        // The custom repository encrypts the XML before persisting it in the shared database.
        services.AddSingleton<IXmlRepository, DatabaseDataProtectionKeyRepository>();
        services.AddSingleton<ConfigurationXmlEncryptor>();
        services.AddDataProtection().SetApplicationName("SignaCore.Admin");
        services.AddOptions<Microsoft.AspNetCore.DataProtection.KeyManagement.KeyManagementOptions>()
            .Configure<IXmlRepository, ConfigurationXmlEncryptor>((options, repository, encryptor) =>
            {
                options.XmlRepository = repository;
                options.XmlEncryptor = encryptor;
            });

        // ---- JWT Options ----
        var jwtOptions = services.RegisterSingleton(new JwtOptions
        {
            Issuer = configuration["Jwt:Issuer"] ?? "SignaCore",
            Audience = configuration["Jwt:Audience"] ?? "SignaCore.Services",
            TokenExpirationHours = int.Parse(configuration["Jwt:TokenExpirationHours"] ?? "2")
        });
        jwtOptions.Validate();
        var allowNonHttpsIssuer = configuration.GetValue("Security:AllowNonHttpsIssuer", false);
        if (!environment.IsDevelopment() && !allowNonHttpsIssuer &&
            (!Uri.TryCreate(jwtOptions.Issuer, UriKind.Absolute, out var issuerUri) ||
             issuerUri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException(
                "Jwt:Issuer must be an absolute HTTPS URL outside the Development environment. " +
                "Set Security:AllowNonHttpsIssuer=true only for a deliberate legacy migration.");
        }
        var publicBaseUrl = configuration[PublicOrigin.ConfigurationKey];
        if (!environment.IsDevelopment() && !allowNonHttpsIssuer &&
            !string.IsNullOrWhiteSpace(publicBaseUrl) &&
            !string.Equals(
                jwtOptions.Issuer.TrimEnd('/'),
                publicBaseUrl.Trim().TrimEnd('/'),
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Jwt:Issuer must match {PublicOrigin.ConfigurationKey} outside the Development environment.");
        }

        // ---- Token Service ----
        services.AddSingleton<ITokenService, JwtTokenService>();

        // ---- Password Hasher ----
        services.RegisterPasswordHashingDefaults(configuration);

        // ---- Refresh Token Options ----
        var refreshTokenOptions = services.RegisterSingleton(new RefreshTokenOptions
        {
            RefreshTokenExpirationDays = int.Parse(configuration["RefreshToken:ExpirationDays"] ?? "7")
        });
        refreshTokenOptions.Validate();

        // ---- LDAP / Active Directory ----
        var ldapOptions = configuration.GetSection(LdapOptions.SectionName).Get<LdapOptions>() ?? new LdapOptions();
        ldapOptions.Validate();
        services.AddSingleton(ldapOptions);
        services.AddSingleton<ILdapDirectoryClient, ActiveDirectoryClient>();
        services.AddScoped<ILdapAccountService, LdapAccountService>();

        // ---- Claims Resolver ----
        services.AddScoped<ClaimsResolver>();

        // ---- Callback Service ----
        var callbackAllowedDomains = configuration.GetSection("Callback:AllowedDomains").Get<string[]>() ?? [];
        var callbackAllowPrivateAddresses = configuration.GetValue(
            "Callback:AllowPrivateAddresses",
            environment.IsDevelopment());
        var callbackRequireHttps = configuration.GetValue(
            "Callback:RequireHttps",
            !environment.IsDevelopment());
        services.AddSingleton(new CallbackUrlValidator(
            callbackAllowedDomains,
            callbackAllowPrivateAddresses,
            callbackRequireHttps));
        services.AddHttpClient("Callback", client =>
            {
                client.Timeout = TimeSpan.FromSeconds(IdentityConstants.CallbackTimeoutSeconds);
                client.MaxResponseContentBufferSize = 64 * 1024;
            })
            .ConfigurePrimaryHttpMessageHandler(() =>
                CallbackHttpMessageHandler.Create(callbackAllowPrivateAddresses));
        services.AddScoped<ICallbackService, CallbackService>();

        // ---- SMS OTP Services ----
        var smsOptions = configuration.GetSection(SmsOptions.SectionName).Get<SmsOptions>() ?? new SmsOptions();
        smsOptions.BypassCode = configuration["Sms:BypassCode"] ?? Environment.GetEnvironmentVariable("SMS_BYPASS_CODE");
        smsOptions.BypassPhones = ResolveBypassPhones(configuration);
        smsOptions.OtpHmacKey = configuration["Sms:OtpHmacKey"] ?? Environment.GetEnvironmentVariable("SMS_OTP_HMAC_KEY");
        if (environment.IsDevelopment() && string.IsNullOrWhiteSpace(smsOptions.OtpHmacKey))
            smsOptions.OtpHmacKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        if (environment.IsDevelopment() && smsOptions.Profiles.Count == 0)
            smsOptions.Profiles["development"] = new SmsProviderProfile { Provider = SmsProviderNames.Logging };
        smsOptions.Validate(environment.IsDevelopment());
        services.AddSingleton(smsOptions);
        services.AddScoped<IOtpService, DbOtpService>();
        // Logging is development-only; production profiles resolve to a real cloud provider.
        services.AddSingleton<ISmsSender, AlibabaCloudSmsSender>();
        services.AddSingleton<ISmsSender, TencentCloudSmsSender>();
        if (environment.IsDevelopment()) services.AddSingleton<ISmsSender, LoggingSmsSender>();
        services.AddSingleton<SmsSenderResolver>();
        services.AddScoped<ISmsAdmissionService, SmsAdmissionService>();

        // ---- WeChat API Client ----
        var wechatOptions = services.RegisterSingleton(new WechatOptions
        {
            AppId = configuration["WeChat:AppId"] ?? string.Empty,
            AppSecret = configuration["WeChat:AppSecret"] ?? string.Empty,
            ApiBaseUrl = configuration["WeChat:ApiBaseUrl"] ?? "https://api.weixin.qq.com"
        });
        wechatOptions.Validate();
        services.AddHttpClient<IWechatApiClient, WechatApiClient>(client =>
        {
            client.BaseAddress = new Uri(wechatOptions.ApiBaseUrl);
            client.Timeout = TimeSpan.FromSeconds(10);
        });
        services.AddScoped<IWechatAdmissionService, WechatAdmissionService>();

        // ---- Repository Layer ----
        services.AddScoped<IAccountRepository, AccountRepository>();
        services.AddScoped<IPasswordCredentialRepository, PasswordCredentialRepository>();
        services.AddScoped<IUserLoginRepository, UserLoginRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IAppRegistrationRepository, AppRegistrationRepository>();
        services.AddScoped<IAppExchangeTrustRepository, AppExchangeTrustRepository>();
        services.AddScoped<ISecurityKeyRepository, SecurityKeyRepository>();
        services.AddScoped<IOtpRepository, OtpRepository>();
        services.AddScoped<ILoginAttemptRepository, LoginAttemptRepository>();
        services.AddScoped<ILoginHistoryRepository, LoginHistoryRepository>();
        services.AddScoped<IAuditLogRepository, AuditLogRepository>();
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IOidcAuthorizationRequestValidator, OidcAuthorizationRequestValidator>();
        services.AddScoped<IUnitOfWork, EfCoreUnitOfWork>();

        // ---- Gateway Validation Service ----
        services.AddScoped<GatewayValidationService>();

        // ---- User Query Service ----
        services.AddScoped<IUserQueryService, UserQueryService>();

        // ---- Refresh Token Service ----
        services.AddScoped<IRefreshTokenService, RefreshTokenService>();
        services.AddScoped<IAccountLoginInfoService, AccountLoginInfoService>();

        // ---- Rate Limiting (ASP.NET Core built-in) ----
        // Per-IP fixed window limiter: 100 requests per 60 seconds per client IP.
        // /health, /metrics and both JWKS routes are exempt (have their own limits or are infra).
        services.AddRateLimiter(options =>
        {
            options.AddPolicy("sms-code", httpContext =>
            {
                // The limiter deliberately runs before authentication so invalid credentials cannot
                // bypass it. AppId is only a partition hint here; authorization still validates it.
                var appId = httpContext.GetAppId() ?? "unknown";
                var clientIp = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                return System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
                    $"{appId}|{clientIp}",
                    _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
                    {
                        AutoReplenishment = true,
                        PermitLimit = 10,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    });
            });
            // The setup and bootstrap endpoints are mapped by every host, so the policies their
            // actions reference have to exist here too even though a configured, completed
            // installation only ever answers 409 from them.
            options.AddPolicy(Controllers.SetupController.RateLimitPolicy, context =>
                System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
                    context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
                    {
                        AutoReplenishment = true,
                        PermitLimit = 5,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    }));
            options.AddPolicy(Controllers.BootstrapController.RateLimitPolicy, context =>
                System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
                    context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
                    {
                        AutoReplenishment = true,
                        PermitLimit = 5,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    }));
            options.AddFixedWindowLimiter("default", opt =>
            {
                opt.AutoReplenishment = true;
                opt.PermitLimit = 100;
                opt.Window = TimeSpan.FromSeconds(60);
            });
            options.GlobalLimiter = System.Threading.RateLimiting.PartitionedRateLimiter.Create<
                Microsoft.AspNetCore.Http.HttpContext,
                string>(httpContext =>
            {
                var path = httpContext.Request.Path.Value ?? string.Empty;
                // Exempt infrastructure endpoints from global rate limiting
                if (path == HealthEndpoints.Legacy || path == HealthEndpoints.Live ||
                    path == HealthEndpoints.Ready || path == "/metrics" ||
                    WellKnownEndpoints.IsJwks(path))
                {
                    return System.Threading.RateLimiting.RateLimitPartition.GetNoLimiter(
                        "infrastructure");
                }

                var remoteIp = httpContext.Connection.RemoteIpAddress ?? System.Net.IPAddress.Loopback;
                return System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
                    $"client:{remoteIp}",
                    _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
                    {
                        AutoReplenishment = true,
                        PermitLimit = 100,
                        Window = TimeSpan.FromSeconds(60)
                    });
            });
            options.OnRejected = async (context, cancellationToken) =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.HttpContext.Response.ContentType = "application/json";
                await context.HttpContext.Response.WriteAsync(
                    """{"status":429,"title":"Too Many Requests","detail":"Rate limit exceeded. Please try again later."}""",
                    cancellationToken);
            };
        });

        // ---- Validators (Auto-registered) ----
        services.AddScoped<IIdentityValidator, PasswordValidator>();
        services.AddScoped<IIdentityValidator, SmsValidator>();
        services.AddScoped<IIdentityValidator, WechatValidator>();
        services.AddScoped<IIdentityValidator, RefreshTokenValidator>();
        services.AddScoped<IIdentityValidator, LdapValidator>();

        // ---- Validator Factory (auto-builds dictionary from injected validators) ----
        services.AddScoped<ValidatorFactory>();

        // ---- Token issuance pipeline shared by /api/auth/token and /oauth2/token ----
        services.AddScoped<TokenIssuanceService>();

        // ---- Background Cleanup Service ----
        services.AddHostedService<CleanupWorker>();

        // ---- Health Checks ----
        // Liveness answers "is this process able to reach its database"; readiness additionally
        // requires that signing keys are loaded, so a starting instance never receives traffic it
        // cannot serve.
        services.AddHealthChecks()
            .AddDbContextCheck<IdentityDbContext>(
                "database",
                tags: [HealthCheckTags.Live, HealthCheckTags.Ready])
            .AddCheck<SigningKeysHealthCheck>(
                "signing-keys",
                tags: [HealthCheckTags.Ready]);

        var adminWebOrigins = configuration.GetSection(SystemSettingKeys.AdminWebAllowedOrigins)
            .Get<string[]>() ?? Array.Empty<string>();
        services.AddSingleton(new AdminIdentityOptions
        {
            Username = configuration[SystemSettingKeys.AdminUsername]?.Trim() ?? string.Empty
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
                        // Production has to configure AdminWeb:AllowedOrigins explicitly, or CORS
                        // stays off.
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
                    // With no origins, only simple requests are allowed and no credentials are
                    // carried.
                    policy.AllowAnyHeader()
                        .AllowAnyMethod();
                }
            });
        });

        // Forwarded headers are honored only from explicitly trusted proxies (plus the framework's
        // loopback defaults). This keeps scheme/client-IP handling correct without trusting spoofed
        // X-Forwarded-* headers from arbitrary clients.
        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                                       ForwardedHeaders.XForwardedProto;
            options.ForwardLimit = 1;
            options.RequireHeaderSymmetry = true;

            foreach (var value in configuration
                         .GetSection("ReverseProxy:KnownProxies")
                         .Get<string[]>() ?? [])
            {
                if (!System.Net.IPAddress.TryParse(value, out var address))
                {
                    throw new InvalidOperationException(
                        $"ReverseProxy:KnownProxies contains an invalid IP address: '{value}'.");
                }

                options.KnownProxies.Add(address);
            }
        });

        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.Cookie.Name = "qz_admin_session";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = environment.IsDevelopment()
                    ? CookieSecurePolicy.SameAsRequest
                    : CookieSecurePolicy.Always;
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
            .AddScheme<AuthenticationSchemeOptions, GatewayAppAuthenticationHandler>(
                GatewayAppAuthenticationDefaults.Scheme,
                _ => { })
            .AddScheme<AuthenticationSchemeOptions, OAuthClientAuthenticationHandler>(
                OAuthClientAuthenticationDefaults.Scheme,
                _ => { })
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = async context =>
                    {
                        var authorization = context.Request.Headers.Authorization.ToString();
                        const string bearerPrefix = "Bearer ";
                        if (!authorization.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase))
                        {
                            return;
                        }

                        var compactToken = authorization[bearerPrefix.Length..].Trim();
                        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                        if (!handler.CanReadToken(compactToken))
                        {
                            return;
                        }

                        string? keyId;
                        try
                        {
                            keyId = handler.ReadJwtToken(compactToken).Header.Kid;
                        }
                        catch (ArgumentException)
                        {
                            return;
                        }

                        if (string.IsNullOrEmpty(keyId))
                        {
                            return;
                        }

                        var manager = context.HttpContext.RequestServices.GetRequiredService<IKeyManager>();
                        if (manager.GetValidationKeys().Any(key =>
                                string.Equals(key.KeyId, keyId, StringComparison.Ordinal)))
                        {
                            return;
                        }

                        await manager.RefreshKeysAsync(context.HttpContext.RequestAborted);
                    }
                };
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtOptions.Issuer,
                    ClockSkew = TimeSpan.FromSeconds(30),
                    // This scheme serves only this service's own /api/profile/*, which is the user
                    // self-service API and belongs to no single application: a user should be able
                    // to manage their own profile with a token issued for any registered
                    // application. So what is decided here is really "did we sign this token?"
                    // rather than audience authorization — it admits the deployment-level shared
                    // audience, or an aud that matches the client_id inside the same token (under
                    // PerApplication mode the two are equal, which amounts to accepting every token
                    // we signed ourselves).
                    //
                    // Note that this does not weaken the goal of AudienceMode. Audience isolation
                    // exists to stop a *downstream service* from taking A's token as B's, and a
                    // downstream service validates with its own ValidAudience, which does not come
                    // through here. Application-level authorization proper is decided by the
                    // client_id claim (see the WeChat binding scope in ProfileController).
                    // See docs/overview/StandardsConformance.md for the details.
                    AudienceValidator = (audiences, securityToken, _) =>
                    {
                        var clientId = (securityToken as System.IdentityModel.Tokens.Jwt.JwtSecurityToken)?
                            .Claims.FirstOrDefault(claim => claim.Type == IdentityConstants.ClaimClientId)?.Value;
                        return audiences.Any(audience =>
                            string.Equals(audience, jwtOptions.Audience, StringComparison.Ordinal)
                            || (clientId != null && string.Equals(audience, clientId, StringComparison.Ordinal)));
                    }
                };
            });
        services.AddAuthorizationBuilder()
            .AddPolicy(GatewayAppAuthenticationDefaults.Policy, policy =>
            {
                policy.AddAuthenticationSchemes(GatewayAppAuthenticationDefaults.Scheme);
                policy.RequireAuthenticatedUser();
            })
            .AddPolicy(OAuthClientAuthenticationDefaults.Policy, policy =>
            {
                policy.AddAuthenticationSchemes(OAuthClientAuthenticationDefaults.Scheme);
                policy.RequireAuthenticatedUser();
            })
            .AddPolicy("AdminSession", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireClaim("admin_access", "true");
            })
            .AddPolicy(GatewayAppAuthenticationDefaults.OpsPolicy, policy =>
            {
                policy.AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme);
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
    /// Password hashing and policy. Setup Mode needs both to create the initial administrator, so
    /// they are registered separately from the rest of the application phase.
    /// </summary>
    internal static IServiceCollection RegisterPasswordHashingDefaults(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        services.AddSingleton(new PasswordHasherOptions
        {
            WorkFactor = configuration?.GetValue(
                SystemSettingKeys.PasswordHasherWorkFactor,
                IdentityConstants.BCryptWorkFactor) ?? IdentityConstants.BCryptWorkFactor
        });
        services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();
        services.AddSingleton<IPasswordPolicy, DefaultPasswordPolicy>();
        return services;
    }

    /// <summary>
    /// Resolves the SMS bypass allow-list. Consul KV holds a JSON array and an environment variable
    /// holds a comma-separated string; both are supported.
    /// An empty list is returned when it is not configured, and then <c>SmsValidator</c> admits no
    /// number at all, even with a BypassCode configured.
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

}
