using Microsoft.AspNetCore.Authentication.JwtBearer;
using Serilog;
using ServiceMantle;
using ServiceMantle.AspNetCore.Health;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using ServiceMantle.Bootstrap;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Configuration;
using SignaCore.Host.HealthChecks;
using SignaCore.Host.Installation;
using SignaCore.Host.Management;
using SignaCore.Host.Middleware;
using SignaCore.Host.Provisioning;
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
    return await InstallationStartup.RotateSetupCodeAsync(builder.Configuration, builder.Environment);
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
// silently pointing the service at the wrong database. The path is resolved once so the banner,
// the pre-composition store, and the DI-registered store all agree.
var bootstrapFilePath = SignaCoreBootstrapStore.ResolveFilePath(builder.Configuration);
BootstrapConfiguration? bootstrap;
try
{
    bootstrap = SignaCoreBootstrapStore.TryLoad(builder.Configuration, builder.Environment);
}
catch (Exception exception)
{
    Console.Error.WriteLine("SignaCore failed to start.");
    Console.Error.WriteLine(exception.Message);
    throw;
}

// ---- Bootstrap Configuration Mode ----
// No database is known, so nothing that needs one is composed. The process stays live, reports
// readiness as false, and serves exactly one workflow: create the bootstrap file through the
// shared anonymous management entry, authorized by a one-time credential this start reissues and
// prints once.
if (bootstrap is null)
{
    // Every start reissues the one-time credential, invalidating the credential of any previous
    // start, and prints the new plaintext exactly once.
    var credentialStartup = await BootstrapCredentialProvisioner.ProvisionAsync(bootstrapFilePath);

    if (credentialStartup.Outcome == BootstrapCredentialStartupOutcome.AlreadyConfigured)
    {
        // Another process published a bootstrap file between the load above and the reissue. This
        // process continues as the configured instance it now is.
        bootstrap = SignaCoreBootstrapStore.TryLoad(builder.Configuration, builder.Environment);
        if (bootstrap is null)
        {
            Console.Error.WriteLine("SignaCore failed to start.");
            Console.Error.WriteLine(
                $"The bootstrap file that appeared at '{bootstrapFilePath}' is no longer readable.");
            return 1;
        }
    }
    else if (credentialStartup.Outcome == BootstrapCredentialStartupOutcome.Failed)
    {
        // The notice with the record path has already been printed; the record is untouched.
        return 1;
    }
    else
    {
        builder.Host.UseAgentSerilog("SignaCore");
        ConfigureKestrel(builder);

        // ---- Bootstrap Configuration Mode composition ----
        // SignaCore's candidate rules replace the shared default before AddServiceMantle's TryAdd
        // could register it; the manager the shared creation entry publishes through owns a store
        // instance over the same resolved path. The mode host has no current master key, so the
        // key-replacement refusal step of the validator is inert here.
        builder.Services.AddSingleton<IBootstrapCandidateValidator>(
            _ => new SignaCoreBootstrapCandidateValidator(
                SignaCoreBootstrapStore.CreateProviderRegistry(),
                currentMasterKey: null));
        builder.Services.AddSingleton<BootstrapConfigurationManager>(provider =>
            new BootstrapConfigurationManager(
                SignaCoreBootstrapStore.Create(builder.Configuration),
                provider.GetRequiredService<InstanceId>(),
                provider.GetRequiredService<IBootstrapCandidateValidator>()!));

        var bootstrapMantle = builder.Services.AddSignaCoreServiceMantle(bootstrapFilePath);
        // The cookie scheme is a prerequisite of the shared Bootstrap group (the update entry it
        // also maps authorizes through it); without a database the key ring stays process-local,
        // which is sound here because no session can be established in this phase anyway.
        bootstrapMantle.AddManagementCookieAuthentication();
        bootstrapMantle.AddServiceMantleManagementApiV1();
        bootstrapMantle.AddServiceMantleBootstrapManagement();
        bootstrapMantle.AddServiceMantleInstallationStatus();
        bootstrapMantle.AddServiceMantleHealthEndpoints();
        bootstrapMantle.AddSecurityResponseHeaders();
        bootstrapMantle.AddRateLimiting();

        // One store instance serves the creation entry's consumption, the probe's non-consuming
        // verification, and the startup reissue that printed the credential.
        builder.Services.AddSingleton(credentialStartup.Store!);
        builder.Services.AddSingleton<IBootstrapCredentialStore>(credentialStartup.Store!);
        builder.Services.AddSingleton<IBootstrapCredentialVerifier>(credentialStartup.Store!);
        builder.Services.AddSingleton<IServiceHealthSnapshotSource, BootstrapModeSnapshotSource>();
        builder.Services.AddSingleton<BootstrapConfigurationService>();

        var bootstrapApp = builder.Build();

        // The restart trigger. The shared restart latch is internal, so the host watches the
        // creation entry itself: after the response completes, the file being published - or a
        // Bootstrap exception proving a file is there but unreadable - stops the process so a
        // supervisor restarts it into the next phase. Deciding on the file rather than the status
        // code keeps a published-but-lost response from stranding a configured instance.
        bootstrapApp.Use(async (context, next) =>
        {
            if (HttpMethods.IsPost(context.Request.Method) &&
                context.Request.Path.StartsWithSegments("/management/v1/bootstrap"))
            {
                // Resolved while the request scope still exists: after the response completes,
                // HttpContext.RequestServices is gone, but the captured singleton is not.
                var manager = context.RequestServices.GetRequiredService<BootstrapConfigurationManager>();
                context.Response.OnCompleted(() =>
                {
                    try
                    {
                        if (!manager.GetStatus().IsConfigured)
                        {
                            return Task.CompletedTask;
                        }
                    }
                    catch (ServiceMantle.Bootstrap.BootstrapException)
                    {
                        // The file is there but unreadable; the restart path owns reporting that.
                    }

                    bootstrapApp.Logger.LogInformation(
                        "The bootstrap file was published; stopping so a supervisor can restart this process.");
                    bootstrapApp.Lifetime.StopApplication();
                    return Task.CompletedTask;
                });
            }

            await next(context);
        });

        bootstrapApp.UseMiddleware<ExceptionHandlingMiddleware>();
        bootstrapApp.UseServiceMantlePipeline();

        bootstrapApp.MapServiceMantleHealthEndpoints();
        bootstrapApp.MapServiceMantleBootstrap();
        bootstrapApp.MapServiceMantleInstallationStatus();
        BootstrapTestEndpoint.Map(bootstrapApp);

        // The console is served by the same mapped fallback the normal host uses, admitted only
        // while the phase is Bootstrap Configuration; once the file exists and the process
        // restarts, the normal host's /bootstrap redirect takes over.
        AdminSpaBranch.MapNormalHostSpaFallback(bootstrapApp, httpPort)
            .WithServiceMantlePhaseAdmission(ServiceStartupPhase.BootstrapConfiguration);

        await bootstrapApp.RunAsync();
        return 0;
    }
}

// ---- Bootstrap phase ----
// Open the business database named by the bootstrap file, migrate it, and decide whether this
// process runs Setup Mode or the normal host. Nothing application-level is composed yet: production
// configuration validation must not run before the installation state is known.
BootstrapPhaseResult bootstrapResult;
try
{
    bootstrapResult = await InstallationStartup.RunAsync(
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

// An unhandled exception terminates the process immediately, while the Loki sink sends batches
// asynchronously. Without this handler, its buffered logs, including the fatal exception itself,
// may be lost and appear only in container stdout. Normal host shutdown flushes the logger; this
// covers the crash path so startup failures can also reach Loki.
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
            bootstrapResult.SetupCodeExpiresAt
                ?? DateTimeOffset.UtcNow.Add(ServiceMantle.Installation.SetupCodeLifetime.MaximumValue));
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

// ---- ServiceMantle host identity, readiness, sensitive Headers and shared HTTP capabilities ----
// The shared health capability, the signing-key readiness contributor, the product sensitive
// Header set, the security response headers and the shared rate-limit policies are registered here
// only: neither the Bootstrap nor the Setup host resolves IKeyManager or serves an
// X-Admin-AppSecret endpoint. No health route is mapped, so /health/live, /health/ready and
// /health keep their current owners and responses. The shared capabilities are registered before
// the host composes its own rate limiter below so its locked rejection contract — the JSON body
// HostRejectionWriteCancellationTests pins — keeps serving every named policy.

// ---- Shared bootstrap update prerequisites ----
// SignaCore's candidate rules and manager replace the shared defaults before AddServiceMantle's
// TryAdd could register them: registered after it, these TryAdds would silently keep the shared
// default validator, which does not enforce the master-key rules of a running host. The manager
// owns a store instance over the same resolved path, exactly like the mode host's registration.
builder.Services.AddSingleton<IBootstrapCandidateValidator>(
    _ => new SignaCoreBootstrapCandidateValidator(
        SignaCoreBootstrapStore.CreateProviderRegistry(),
        currentMasterKey: bootstrapResult.Bootstrap.MasterKey));
builder.Services.AddSingleton<BootstrapConfigurationManager>(provider =>
    new BootstrapConfigurationManager(
        SignaCoreBootstrapStore.Create(builder.Configuration),
        provider.GetRequiredService<InstanceId>(),
        provider.GetRequiredService<IBootstrapCandidateValidator>()!));

var mantle = builder.Services.AddSignaCoreServiceMantle(bootstrapFilePath);
mantle.AddSignaCoreSharedHttpCapabilities();

// ---- Infrastructure (DI, Auth, CORS, Rate Limiting, OpenTelemetry) ----
var (jwtOptions, dbProvider) = builder.Services.AddIdentityInfrastructure(
    builder.Configuration,
    builder.Environment,
    SignaCoreBootstrapStore.ToDatabaseOptions(bootstrapResult.Bootstrap.Database),
    bootstrapResult.MasterKeyProvider);

// ---- Shared ServiceMantle management session (fixed cookie scheme, phase gate, session entries) ----
mantle.AddSignaCoreManagementSession(
    SignaCoreBootstrapStore.ToDatabaseOptions(bootstrapResult.Bootstrap.Database));

// The shared bootstrap group: the update entry the authenticated editor drives. The credential
// store is only constructed — never provisioned or issued here — because the shared mapping
// requires a registered store to start; on this host the creation entry is phase-gated to a
// 503 anyway, so the credential is never consumed.
mantle.AddServiceMantleBootstrapManagement();
builder.Services.AddSingleton<IBootstrapCredentialStore>(
    BootstrapCredentialProvisioner.CreateStore(bootstrapFilePath));

builder.Services.AddSingleton(bootstrapResult.RuntimeState);
builder.Services.AddSingleton(bootstrapResult.SettingsStore);

// ---- Shared ServiceMantle setting stack (parallel to the legacy system_settings path) ----
builder.Services.AddSignaCoreSharedSettings(
    SignaCoreBootstrapStore.ToDatabaseOptions(bootstrapResult.Bootstrap.Database),
    builder.Environment.IsDevelopment());

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
    BootstrapDiagnostics.DescribeEndpoint(bootstrapResult.Bootstrap.Database));
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
// optional bootstrap-apps.json pre-seed, which is a product capability rather than migration work.
using (var seedScope = app.Services.CreateScope())
{
    await BootstrapAppSeeder.SeedBootstrapAppsAsync(
        builder.Configuration,
        seedScope.ServiceProvider.GetRequiredService<IdentityDbContext>(),
        seedScope.ServiceProvider.GetRequiredService<IAuditService>(),
        seedScope.ServiceProvider.GetRequiredService<IPasswordHasher>(),
        app.Services
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger(typeof(BootstrapAppSeeder).FullName!),
        seedScope.ServiceProvider.GetRequiredService<IHostEnvironment>().IsDevelopment(),
        app.Lifetime.ApplicationStopping);
}

// ---- Wait for KeyManager initialization before accepting requests ----
var keyManager = app.Services.GetRequiredService<IKeyManager>();
await keyManager.InitializationCompleted;
app.Logger.LogInformation("KeyManager initialization verified");

// ---- Configure JWT Bearer signing key resolver after KeyManager is ready ----
var jwtBearerOptions = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<JwtBearerOptions>>();
var bearerOptions = jwtBearerOptions.Get(JwtBearerDefaults.AuthenticationScheme);
// Return every unexpired key, matching the set published by JWKS, rather than only the current
// signing key. Otherwise, during rotation this service would reject its own still-valid tokens
// signed by the previous key while downstream services continue to accept them.
// GetValidationKeys returns an in-memory snapshot without a database round trip.
bearerOptions.TokenValidationParameters.IssuerSigningKeyResolver =
    (_, _, _, _) => keyManager.GetValidationKeys();

// ---- Swagger (Development only) ----
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Identity Service API v1"));
}
app.UseForwardedHeaders();
app.UseMiddleware<ExceptionHandlingMiddleware>();
app.UseCors("AdminWeb");
// Redaction moves ahead of the composed pipeline: it ran between authentication and authorization
// before, and the gateway schemes still authenticate on demand deeper in the pipeline through
// HttpContextExtensions, which prefers the protected Items copy.
app.UseMiddleware<SensitiveHeaderRedactionMiddleware>();
// The composed ServiceMantle pipeline replaces the individually inserted correlation-id,
// rate-limiting, authentication, and authorization middleware. It must be called exactly once and
// must not be mixed with the individual ServiceMantle entry points.
app.UseServiceMantlePipeline();

// The bootstrap update guard runs after the shared pipeline — so its 401/403 still precede the
// host rules — and before the endpoint: it refuses a Development-fallback host and an
// unconfirmed database change without calling the shared handler, and it owns the
// bootstrap_updated audit row and the controlled stop after a published update.
app.UseMiddleware<BootstrapUpdateGuardMiddleware>();

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
        context.Request.Path.StartsWithSegments(FirstRunPaths.Bootstrap))
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
            await context.Response.WriteAsync(
                "Too many requests to JWKS endpoint. Please try again later.", context.RequestAborted);
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
// Serve the same document at both standard paths: OIDC Discovery's openid-configuration and RFC
// 8414's oauth-authorization-server. The issuer must exactly match the token's iss claim, so use
// JwtOptions.Issuer instead of repeating a literal value.
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
async Task<IResult> GetJwks(IKeyManager keys, CancellationToken cancellationToken)
{
    var validKeys = await keys.GetValidKeysAsync(cancellationToken);
    var jwks = validKeys.Select(JwksMapper.ToJwk);
    return Results.Ok(new { keys = jwks });
}

app.MapGet(WellKnownEndpoints.Jwks, GetJwks);
app.MapGet(WellKnownEndpoints.JwksJson, GetJwks);

app.MapControllers();

// ---- Shared ServiceMantle management session (login / current session / logout) ----
app.MapSignaCoreManagementSession();

// ---- Shared bootstrap entries (update; creation stays phase-gated to 503 on this host) ----
app.MapServiceMantleBootstrap();

// ---- Authenticated bootstrap overview and target probe ----
AdminBootstrapEndpoints.Map(app);

// ---- Prometheus Metrics Endpoint ----
app.MapPrometheusScrapingEndpoint();

// ---- Static files & SPA for Admin Web (HTTP port only) ----
// The normal host composes the ServiceMantle pipeline, whose phase gate 404s endpoint-less requests,
// so the SPA is served by a mapped GET/HEAD fallback endpoint rather than a post-pipeline branch.
AdminSpaBranch.MapNormalHostSpaFallback(app, httpPort);

await app.RunAsync();
return 0;

public partial class Program { }
