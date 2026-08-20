using Microsoft.AspNetCore.Authentication.JwtBearer;
using Serilog;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Configuration;
using SignaCore.Host.HealthChecks;
using SignaCore.Host.Installation;
using SignaCore.Host.Middleware;
using SignaCore.Host.Security;
using SignaCore.Host.Startup;

var builder = WebApplication.CreateBuilder(args);

using var bootstrapLoggerFactory = LoggerFactory.Create(logging =>
{
    logging.AddSimpleConsole(options => options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff ");
});

// ---- Operator command: reissue the one-time setup code ----
// Allowed only while the installation is Pending, requires access to the bootstrap secret, uses the
// database lock, and prints the new code once. It can never reset a Completed installation.
if (args.Contains("--rotate-setup-code", StringComparer.Ordinal))
{
    return await BootstrapPhase.RotateSetupCodeAsync(builder.Configuration, builder.Environment);
}

// The listening port is a deployment concern owned by the launcher, not database-backed
// configuration, so it keeps coming from appsettings/environment. It is resolved before the
// bootstrap phase because Bootstrap Configuration Mode needs it too.
var httpPort = builder.Configuration.GetValue<int?>("Endpoints:Http") ?? 5002;

void ConfigureKestrel(WebApplicationBuilder target)
{
    target.WebHost.ConfigureKestrel(options =>
    {
        options.ListenAnyIP(httpPort, listenOptions =>
        {
            listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1;
        });
        options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
    });
    target.Services.Configure<Microsoft.Extensions.Hosting.HostOptions>(options =>
    {
        options.ShutdownTimeout = TimeSpan.FromSeconds(30);
    });
}

// ---- Bootstrap file ----
// A missing bootstrap file is not a failure: the operator has not configured this deployment yet.
// A malformed one is, because ignoring a bootstrap someone did write is indistinguishable from
// silently pointing the service at the wrong database.
BootstrapConfiguration? bootstrap;
try
{
    bootstrap = BootstrapLoader.TryLoad(builder.Configuration, builder.Environment);
}
catch (Exception exception)
{
    Console.Error.WriteLine("SignaCore failed to start.");
    Console.Error.WriteLine(exception.Message);
    throw;
}

// ---- Bootstrap Configuration Mode ----
// No database is known, so nothing that needs one is composed. The process stays live, reports
// readiness as false, and serves exactly one workflow: create the bootstrap file.
if (bootstrap is null)
{
    var codeAuthority = BootstrapCodeAuthority.Create(out var bootstrapCode);
    StartupBanner.WriteBootstrapCode(
        bootstrapCode,
        BootstrapLoader.ResolveFilePath(builder.Configuration),
        codeAuthority.ExpiresAt);
    StartupBanner.WriteBootstrapModeNotice();

    builder.Host.UseAgentSerilog("SignaCore");
    ConfigureKestrel(builder);
    BootstrapModeHost.ConfigureServices(builder, codeAuthority);

    var bootstrapApp = builder.Build();
    BootstrapModeHost.ConfigurePipeline(bootstrapApp, httpPort);

    bootstrapApp.Lifetime.ApplicationStopping.Register(() =>
    {
        if (bootstrapApp.Services.GetRequiredService<BootstrapCodeAuthority>().IsConsumed)
        {
            StartupBanner.WriteRestartInstruction();
        }
    });

    await bootstrapApp.RunAsync();
    return 0;
}

// ---- Bootstrap phase ----
// Open the business database named by the bootstrap file, migrate it, and decide whether this
// process runs Setup Mode or the normal host. Nothing application-level is composed yet: production
// configuration validation must not run before the installation state is known.
BootstrapPhaseResult bootstrapResult;
try
{
    bootstrapResult = await BootstrapPhase.RunAsync(
        bootstrap,
        builder.Configuration,
        builder.Environment,
        bootstrapLoggerFactory);
}
catch (Exception exception)
{
    // Startup diagnostics never carry the connection string or the root key; the loader and the
    // snapshot validator both produce messages that are safe to print here.
    Console.Error.WriteLine("SignaCore failed to start.");
    Console.Error.WriteLine(exception.Message);
    throw;
}

// ---- Legacy override diagnostics ----
// The database is authoritative now. Values still supplied by appsettings, environment variables, or
// the launcher are inert; report them so operators can remove them.
var legacyOverrides = LegacyConfigurationGuard.FindManagedOverrides(builder.Configuration);
var hasLegacyDatabaseSection = LegacyConfigurationGuard.HasDatabaseSectionOverride(builder.Configuration);

// ---- Activate the configuration snapshot ----
// Layered last so the database wins over every deployment-provided source.
if (bootstrapResult.Snapshot is not null)
{
    builder.Configuration.AddInMemoryCollection(bootstrapResult.Snapshot.ConfigurationEntries);
}

// ---- Serilog (Console + Grafana Loki) ----
// The Loki sink throws on a null uri, so the address is only patched in when the snapshot supplies
// one. Loki being unreachable is not fatal: the sink retries asynchronously.
var lokiUri = builder.Configuration[SystemSettingKeys.LokiUri];
if (!string.IsNullOrWhiteSpace(lokiUri))
{
    builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["Serilog:WriteTo:1:Args:uri"] = lokiUri
    });
}

builder.Host.UseAgentSerilog("SignaCore");

// 未处理异常会让进程立刻退出，而 Loki Sink 是批量异步投递的，缓冲区里的日志
// （包括致命异常本身）会整批丢失，只能进容器 stdout。正常关停时 host 释放
// logger 会刷盘，这里补上崩溃退出这条路径，让启动失败的原因也能进 Loki。
AppDomain.CurrentDomain.UnhandledException += (_, eventArgs) =>
{
    if (eventArgs.ExceptionObject is Exception unhandled)
    {
        Log.Fatal(unhandled, "Application terminated unexpectedly");
    }

    Log.CloseAndFlush();
};

ConfigureKestrel(builder);

// ---- Setup Mode ----
if (bootstrapResult.Phase != InstallationPhase.Completed)
{
    if (bootstrapResult.PlaintextSetupCode is not null)
    {
        StartupBanner.WriteSetupCode(
            bootstrapResult.PlaintextSetupCode,
            DateTimeOffset.UtcNow.Add(SetupCode.DefaultLifetime));
    }

    StartupBanner.WriteSetupModeNotice();

    SetupModeHost.ConfigureServices(builder, bootstrapResult);
    var setupApp = builder.Build();
    SetupModeHost.ConfigurePipeline(setupApp, httpPort);

    setupApp.Lifetime.ApplicationStopping.Register(() =>
    {
        if (setupApp.Services.GetRequiredService<InstallationRuntimeState>().SetupCompleted)
        {
            StartupBanner.WriteRestartInstruction();
        }
    });

    await setupApp.RunAsync();
    return 0;
}

// ---- Consul Service Discovery (optional) ----
builder.Services.AddConsulDiscoveryIfEnabled(builder.Configuration);

// ---- Infrastructure (DI, Auth, CORS, 限流, OpenTelemetry) ----
var (jwtOptions, dbProvider) = builder.Services.AddIdentityInfrastructure(
    builder.Configuration,
    builder.Environment,
    bootstrapResult.Bootstrap.Database,
    bootstrapResult.MasterKeyProvider);

builder.Services.AddSingleton(bootstrapResult.RuntimeState);
builder.Services.AddSingleton(bootstrapResult.SettingsStore);

// The authenticated bootstrap editor needs the root secret verbatim so a database change can keep
// the current key without asking the operator to retype it. It is registered as the internal
// bootstrap record rather than as a bare string so nothing else can resolve it by accident.
builder.Services.AddSingleton(bootstrapResult.Bootstrap);
builder.Services.AddSingleton<BootstrapConfigurationService>();

var app = builder.Build();

app.Logger.LogInformation("Service endpoints configured: HTTP={HttpPort}", httpPort);
app.Logger.LogInformation(
    "Database: {Provider} at {Endpoint}",
    dbProvider,
    bootstrapResult.Bootstrap.DatabaseEndpointForDiagnostics);
app.Logger.LogInformation(
    "Installation: Id={InstallationId}, ConfigurationVersion={ConfigurationVersion}",
    bootstrapResult.RuntimeState.InstallationId,
    bootstrapResult.RuntimeState.ConfigurationVersion);

if (hasLegacyDatabaseSection)
{
    app.Logger.LogWarning(
        "A 'Database' section is present in appsettings or the environment. The bootstrap " +
        "file is the only source for the database connection; the section is ignored. Remove it.");
}

if (legacyOverrides.Count > 0)
{
    app.Logger.LogWarning(
        "Legacy application-setting overrides are present and ignored; the database is authoritative " +
        "for these keys. Remove them from the launcher: {Keys}",
        string.Join(", ", legacyOverrides));
}

// ---- Discovery conformance diagnostics ----
// The snapshot validator accepts a non-HTTPS issuer only after an explicit operator opt-in.
var configuredIssuer = app.Services.GetRequiredService<JwtOptions>().Issuer;
if (!Uri.TryCreate(configuredIssuer, UriKind.Absolute, out var issuerUri) ||
    issuerUri.Scheme != Uri.UriSchemeHttps)
{
    app.Logger.LogWarning(
        "Jwt:Issuer is {Issuer}, which is not an absolute https URL. OAuth/OIDC clients that validate "
        + "the issuer against the discovery URL will reject tokens issued by this service.",
        configuredIssuer);
}

// ---- HTTPS Warning for Gateway API ----
// Gateway API transmits AppSecret via request headers; warn if not running behind HTTPS/TLS.
// Note: Kestrel configured via ConfigureKestrel may not populate app.Urls; this is a best-effort check.
var hasHttpsEndpoint = app.Urls.Any(url => url.StartsWith("https://", StringComparison.OrdinalIgnoreCase));
if (!hasHttpsEndpoint)
{
    app.Logger.LogWarning(
        "No HTTPS endpoint detected. Gateway API (X-Admin-AppSecret header) will transmit secrets over plain HTTP. " +
        "In production, enable HTTPS or ensure TLS termination at the reverse proxy.");
}

// ---- Application-phase data seeding ----
// Schema migration and installation state were settled in the bootstrap phase; what is left is the
// optional bootstrap-apps.json pre-seed.
await DatabaseInitializer.InitializeAsync(app.Services, builder.Configuration);

// ---- Wait for KeyManager initialization before accepting requests ----
var keyManager = app.Services.GetRequiredService<IKeyManager>();
await keyManager.InitializationCompleted;
app.Logger.LogInformation("KeyManager initialization verified");

// ---- Configure JWT Bearer signing key resolver after KeyManager is ready ----
var jwtBearerOptions = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<JwtBearerOptions>>();
var bearerOptions = jwtBearerOptions.Get(JwtBearerDefaults.AuthenticationScheme);
// 返回全部未过期密钥（与 JWKS 发布的是同一批），而不是只返回当前签名密钥：
// 否则轮换瞬间，本服务会拒掉自己刚签发、仍在有效期内的旧密钥 token，而下游微服务却认。
// GetValidationKeys 是纯内存快照，不做 DB 往返。
bearerOptions.TokenValidationParameters.IssuerSigningKeyResolver =
    (_, _, _, _) => keyManager.GetValidationKeys();

// ---- Swagger（仅开发环境）----
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Identity Service API v1"));
}
app.UseForwardedHeaders();
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseCors("AdminWeb");
// Rate limiting must run before authentication/authorization. Both gateway schemes perform a
// database lookup (and valid AppIds additionally verify a BCrypt secret), so rejected credentials
// must not be able to bypass the limiter by short-circuiting in authorization.
app.UseRateLimiter();
app.UseAuthentication();

// ---- Sensitive Header Redaction Middleware ----
// Moves X-Admin-AppSecret out of the request headers before authorization so
// downstream logging cannot expose it. GatewayApp authentication reads the
// value through HttpContextExtensions, which prefers the protected Items copy.
app.UseMiddleware<SensitiveHeaderRedactionMiddleware>();

app.UseAuthorization();

// ---- Health ----
app.MapHealthChecks(HealthEndpoints.Live, new()
{
    Predicate = registration => registration.Tags.Contains(HealthCheckTags.Live)
});
app.MapHealthChecks(HealthEndpoints.Ready, new()
{
    Predicate = registration => registration.Tags.Contains(HealthCheckTags.Ready)
});
// Compatibility alias: existing launchers and Consul checks poll /health for readiness.
app.MapHealthChecks(HealthEndpoints.Legacy, new()
{
    Predicate = registration => registration.Tags.Contains(HealthCheckTags.Ready)
});

// A completed installation must never re-enter setup. Browser navigation goes to the console; the
// API surface is handled by SetupClosedController. This is middleware rather than a mapped endpoint
// because the setup-mode host serves the same path from the SPA branch, and the branch's guard list
// has to stay identical between the two hosts.
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments(SetupModeGateMiddleware.SetupPath) ||
        context.Request.Path.StartsWithSegments(BootstrapModeGateMiddleware.BootstrapPath))
    {
        context.Response.Redirect("/admin");
        return;
    }

    await next(context);
});

// ---- JWKS Rate Limiting ----
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
    if (WellKnownEndpoints.IsJwks(context.Request.Path.Value ?? string.Empty))
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

// ---- Discovery metadata ----
// 同一份文档挂两个标准路径：OIDC Discovery 的 openid-configuration 与
// RFC 8414 的 oauth-authorization-server。issuer 必须与 token 里的 iss 完全相同，
// 所以取 JwtOptions.Issuer，而不是再写一遍字面量。
IResult BuildDiscoveryDocument(HttpContext httpContext, IConfiguration configuration) =>
    Results.Ok(DiscoveryDocument.Create(
            app.Services.GetRequiredService<JwtOptions>().Issuer,
            PublicOrigin.Resolve(httpContext.Request, configuration),
            httpContext.RequestServices.GetRequiredService<ValidatorFactory>().GetSupportedGrantTypes())
        .ToMetadata());

app.MapGet("/.well-known/openid-configuration", BuildDiscoveryDocument);
app.MapGet("/.well-known/oauth-authorization-server", BuildDiscoveryDocument);

// ---- JWKS Discovery ----
// One handler, two routes. Discovery advertises WellKnownEndpoints.Jwks; the .json alias exists
// because that is what operators and hand-configured validators try first, and a 404 from a key
// endpoint reads as "no keys published". See WellKnownEndpoints for why the alias is kept.
async Task<IResult> GetJwks(IKeyManager keys)
{
    var validKeys = await keys.GetValidKeysAsync();
    var jwks = validKeys.Select(JwksMapper.ToJwk);
    return Results.Ok(new { keys = jwks });
}

app.MapGet(WellKnownEndpoints.Jwks, GetJwks);
app.MapGet(WellKnownEndpoints.JwksJson, GetJwks);

app.MapControllers();

// ---- Prometheus Metrics Endpoint ----
app.MapPrometheusScrapingEndpoint();

// ---- Static files & SPA for Admin Web (HTTP port only) ----
AdminSpaBranch.Map(app, httpPort);

await app.RunAsync();
return 0;

public partial class Program { }
