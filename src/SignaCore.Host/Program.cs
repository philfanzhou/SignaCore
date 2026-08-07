using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Controllers;
using SignaCore.Host.Middleware;
using SignaCore.Host.Security;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// ---- Consul Configuration Source ----
// Identity 固定接入 Consul，按 config/signacore 单层共享路径加载 Consul KV，失败时回退本地缓存。
builder.Configuration.AddConsulIfEnabled(builder.Configuration);

// ---- Serilog (Console + Grafana Loki) ----
// Loki 地址统一来自配置键 Loki:Uri（优先由 Consul KV 提供），覆盖 appsettings.json 中的 fallback。
// Loki Sink 在 uri 为 null 时会抛 ArgumentNullException，配置文件中提供 fallback uri 确保服务能启动。
// Loki 不可达时 Sink 异步重试，不影响服务运行。
var lokiUri = builder.Configuration["Loki:Uri"];
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
// UseAgentSerilog 使用默认的 preserveStaticLogger: false，Log.Logger 即宿主实际使用的 logger。
AppDomain.CurrentDomain.UnhandledException += (_, args) =>
{
    if (args.ExceptionObject is Exception exception)
    {
        Log.Fatal(exception, "Application terminated unexpectedly");
    }

    Log.CloseAndFlush();
};

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

// ---- Consul Service Discovery ----
// 通过 Steeltoe.Discovery.Consul 注册服务实例。
// 健康检查路径：/health（由 Steeltoe 自动配置），间隔 10s，超时 10s。
builder.Services.AddConsulDiscoveryIfEnabled(builder.Configuration);

// ---- Infrastructure (DI, Auth, CORS, 限流, OpenTelemetry) ----
var (jwtOptions, dbProvider) = builder.Services.AddIdentityInfrastructure(builder.Configuration, builder.Environment);

var app = builder.Build();
var consulRuntimeState = app.Services.GetRequiredService<ConsulRuntimeState>();
var consulOptions = ConsulOptions.Bind(app.Configuration);

var effectiveDatabaseProvider = app.Configuration["Database:Provider"];
var effectiveDatabaseServerVersion = app.Configuration["Database:ServerVersion"];
var effectiveLokiUri = app.Configuration["Loki:Uri"];

app.Logger.LogInformation("Service endpoints configured: HTTP={HttpPort}", httpPort);
app.Logger.LogInformation("Database: {Provider}", dbProvider);
app.Logger.LogInformation(
    "Consul startup diagnostics: Address={Address}, Token={Token}, Source={Source}, KeyCount={KeyCount}, Prefixes={Prefixes}, LastError={LastError}",
    $"{consulOptions.Host}:{consulOptions.Port}",
    StartupDiagnosticsFormatter.MaskSecret(consulOptions.Token),
    consulRuntimeState.Source,
    consulRuntimeState.KeyCount,
    StartupDiagnosticsFormatter.SummarizePrefixes(consulRuntimeState.LoadedPrefixes),
    StartupDiagnosticsFormatter.SummarizeError(consulRuntimeState.LastError));
app.Logger.LogInformation(
    "Effective configuration diagnostics: DatabaseProvider={DatabaseProvider}, DatabaseServerVersion={DatabaseServerVersion}, LokiUri={LokiUri}",
    StartupDiagnosticsFormatter.SummarizeValue(effectiveDatabaseProvider),
    StartupDiagnosticsFormatter.SummarizeValue(effectiveDatabaseServerVersion),
    StartupDiagnosticsFormatter.SummarizeValue(effectiveLokiUri));

// ---- Discovery conformance diagnostics ----
// OIDC/OAuth metadata requires the issuer to be an https URL, and every conforming client compares
// the `iss` claim against the URL it fetched discovery from. The default deployment identifier
// ("SignaCore") is kept for backward compatibility with existing downstream validators, so this is a
// warning rather than a hard failure — see docs/overview/StandardsConformance.md.
PublicOrigin.Validate(builder.Configuration);
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

// ---- Database Initialization (must happen before KeyManager) ----
// Auto migration is always enabled. DatabaseInitializer handles migrations,
// schema reconciliation, admin bootstrap, and optional bootstrap-apps.json pre-seeding.
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
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseCors("AdminWeb");
app.UseAuthentication();

// ---- Sensitive Header Redaction Middleware ----
// Moves X-Admin-AppSecret out of the request headers before authorization so
// downstream logging cannot expose it. GatewayApp authentication reads the
// value through HttpContextExtensions, which prefers the protected Items copy.
app.UseMiddleware<SensitiveHeaderRedactionMiddleware>();

app.UseAuthorization();
app.UseRateLimiter();

app.MapHealthChecks("/health");
app.MapGet("/consul/status", (ConsulRuntimeState state) => Results.Ok(state.Snapshot()))
    .RequireAuthorization(GatewayAppAuthenticationDefaults.OpsPolicy);
app.MapPost("/consul/cache/invalidate", (IConfiguration configuration, ConsulRuntimeState state) =>
{
    if (!ConsulOptions.IsEnabled(configuration))
    {
        return Results.Ok(new
        {
            invalidated = false,
            reason = "Consul mode is off"
        });
    }

    var options = ConsulOptions.Bind(configuration);
    using var cacheService = new ConsulCacheService(options.CacheDirectory);
    cacheService.Invalidate();
    state.MarkCacheInvalidated();

    return Results.Ok(new
    {
        invalidated = true,
        cacheDirectory = options.CacheDirectory
    });
}).RequireAuthorization(GatewayAppAuthenticationDefaults.OpsPolicy);

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
app.MapGet("/.well-known/jwks", async (IKeyManager keyManager) =>
{
    var keys = await keyManager.GetValidKeysAsync();
    var jwks = keys.Select(JwksMapper.ToJwk);
    return Results.Ok(new { keys = jwks });
});

app.MapControllers();

// ---- Prometheus Metrics Endpoint ----
app.MapPrometheusScrapingEndpoint();

// ---- Static files & SPA for Admin Web (HTTP port only) ----
var appTitle = builder.Configuration["APP_TITLE"] ?? "SignaCore";
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
                    content = AdminSpaTitleInjector.Inject(content, appTitle);
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
