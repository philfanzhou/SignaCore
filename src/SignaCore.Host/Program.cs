using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using ServiceMantle;
using ServiceMantle.Audit;
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
using SignaCore.Host.Installation;
using SignaCore.Host.Logging;
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
        // No setting snapshot exists in this mode, so the shared pipeline writes to the Console only.
        builder.AddSignaCoreConsoleLogging();
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
if (bootstrapResult.ConfigurationEntries is not null)
{
    builder.Configuration.AddInMemoryCollection(bootstrapResult.ConfigurationEntries);
}

// ---- Logging (ServiceMantle Serilog: Console, plus Grafana Loki on the normal host) ----
// Setup Mode has no setting snapshot yet and writes to the Console only. The normal host takes the
// Loki endpoint and Authorization value from the activated snapshot; values an older release
// stored that Loki can no longer use switch Loki off with a startup warning instead of failing the
// start, so an administrator can still sign in and correct them. The ServiceMantle lifecycle
// flushes the pipeline once on shutdown and on an unhandled exception after the host started.
LokiSettingState? lokiSettings = null;
if (bootstrapResult.Phase == InstallationPhase.Completed)
{
    lokiSettings = builder.AddSignaCoreLogging(bootstrapResult.SharedSnapshot!);
}
else
{
    builder.AddSignaCoreConsoleLogging();
}

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

    // ---- PendingSetup host composition ----
    // Mirrors the Bootstrap Configuration Mode host: the shared management capabilities, the shared
    // pipeline with its phase gate, the shared setup entry, and the admin SPA — nothing that needs
    // the (not yet existing) configuration snapshot is composed, which is precisely why setup
    // cannot start a half-configured identity service. The capability set matches the shared
    // entry's startable baseline; a missing capability fails the host start.
    var setupDatabaseOptions = SignaCoreBootstrapStore.ToDatabaseOptions(bootstrapResult.Bootstrap.Database);
    var setupMantle = builder.Services.AddSignaCoreServiceMantle(bootstrapFilePath);
    setupMantle.AddSensitiveHeaders();
    setupMantle.AddSecurityResponseHeaders();
    setupMantle.AddRateLimiting();
    setupMantle.AddManagementCookieAuthentication();
    setupMantle.AddServiceMantleManagementApiV1();
    setupMantle.AddServiceMantleManagementEntries();
    setupMantle.AddServiceMantleHealthEndpoints();

    builder.Services.AddSingleton(setupDatabaseOptions);
    builder.Services.AddSingleton(bootstrapResult.MasterKeyProvider);

    // The setup completion transaction must run exactly once per request: a retrying execution
    // strategy would replay the whole user transaction, which the shared entry contract forbids.
    builder.Services.AddDbContext<IdentityDbContext>(options =>
        options.UseIdentityDatabase(setupDatabaseOptions, enableRetryOnFailure: false));
    // The completion writes the shared service_settings aggregate through the same transactional
    // update service the normal host composes; no snapshot services exist before the first
    // snapshot can.
    builder.Services.AddSignaCoreSharedSettingUpdates(builder.Environment.IsDevelopment());
    // The shared setup entry reads the installation authority through this store; the readiness
    // snapshot reads it through the same source below.
    builder.Services.AddScoped<ServiceMantle.Installation.IServiceInstallationStore>(
        serviceProvider => InstallationStores.CreateInstallationStore(
            serviceProvider.GetRequiredService<IdentityDbContext>()));
    builder.Services.AddScoped<IServiceHealthSnapshotSource, InstallationHealthSnapshotSource>();

    builder.Services.RegisterPasswordHashingDefaults();
    // The per-request contributor factory the completion executor resolves inside its fresh scope;
    // scoped so every completion binds its contributor to that scope's IdentityDbContext.
    builder.Services.AddScoped<InitialAdministratorSetupContributorFactory>();

    var setupApp = builder.Build();

    // The restart trigger, same shape as the Bootstrap Configuration Mode host: after the response
    // completes, the persisted installation state — not an in-process flag — decides whether this
    // process stops so a supervisor restarts it into the normal host. Deciding on the persisted
    // state means an instance that lost the completion race also restarts, and a response lost in
    // transit never strands a completed installation in Setup Mode.
    setupApp.Use(async (context, next) =>
    {
        if (HttpMethods.IsPost(context.Request.Method) &&
            context.Request.Path.StartsWithSegments("/management/v1/setup"))
        {
            // Resolved while the request scope still exists; the root factory outlives the request.
            var scopeFactory = context.RequestServices.GetRequiredService<IServiceScopeFactory>();
            context.Response.OnCompleted(async () =>
            {
                try
                {
                    await using var scope = scopeFactory.CreateAsyncScope();
                    var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
                    var completed = await db.ServiceInstallations.AsNoTracking().AnyAsync(
                        row => row.ServiceId == InstallationStores.ServiceIdValue &&
                               row.Status == InstallationStatus.Completed,
                        CancellationToken.None);
                    if (!completed)
                    {
                        return;
                    }
                }
                catch
                {
                    // A read failure must not stop the host; the next request or restart re-decides.
                    return;
                }

                setupApp.Logger.LogInformation(
                    "First-run setup completed; stopping so a supervisor can restart this process.");
                setupApp.Lifetime.StopApplication();
            });
        }

        await next(context);
    });

    setupApp.UseMiddleware<ExceptionHandlingMiddleware>();
    setupApp.UseServiceMantlePipeline();

    setupApp.MapServiceMantleHealthEndpoints();
    setupApp.MapServiceMantleSetup(SetupCompletionExecutor.ExecuteAsync);

    // The console is served by the same mapped fallback the normal host uses, admitted only while
    // the phase is PendingSetup; the SPA itself probes the setup entry and renders the setup form.
    AdminSpaBranch.MapNormalHostSpaFallback(setupApp, httpPort)
        .WithServiceMantlePhaseAdmission(ServiceStartupPhase.PendingSetup);

    // A manually launched process has no supervisor: say so explicitly, but only when the
    // persisted state really completed installation during this process's lifetime.
    setupApp.Lifetime.ApplicationStopping.Register(() =>
    {
        try
        {
            using var scope = setupApp.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            if (db.ServiceInstallations.AsNoTracking().Any(
                    row => row.ServiceId == InstallationStores.ServiceIdValue &&
                           row.Status == InstallationStatus.Completed))
            {
                StartupBanner.WriteRestartInstruction();
            }
        }
        catch
        {
            // A state read failure at shutdown is not worth another diagnostic; the operator
            // restart path is documented for every other failure too.
        }
    });

    await setupApp.RunAsync();
    return 0;
}

// ---- Consul Service Discovery (optional, snapshot-driven shared lifecycle) ----
// The product snapshot activated by the bootstrap phase is projected in memory onto the shared
// discovery catalog and drives one shared Consul lifecycle owner. Registration changes of every
// kind take effect after a restart; the Bootstrap and Setup hosts above compose nothing here.
await builder.Services.AddConsulDiscoveryLifecycleAsync(
    builder.Configuration,
    bootstrapResult.SharedSnapshot!,
    bootstrapResult.MasterKeyProvider);

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

// The shared setup entry is mapped on this host too: with the installation Completed it answers
// the status read with "completed" and refuses every completion with the fixed 409 without
// parsing the request body. The handler needs the installation authority through this store.
builder.Services.AddScoped<ServiceMantle.Installation.IServiceInstallationStore>(
    serviceProvider => InstallationStores.CreateInstallationStore(
        serviceProvider.GetRequiredService<IdentityDbContext>()));

// The shared bootstrap group: the update entry the authenticated editor drives. The credential
// store is only constructed — never provisioned or issued here — because the shared mapping
// requires a registered store to start; on this host the creation entry is phase-gated to a
// 503 anyway, so the credential is never consumed.
mantle.AddServiceMantleBootstrapManagement();
builder.Services.AddSingleton<IBootstrapCredentialStore>(
    BootstrapCredentialProvisioner.CreateStore(bootstrapFilePath));

builder.Services.AddSingleton(bootstrapResult.RuntimeState);

// The bootstrap phase activated the runtime snapshot on this exact accessor instance. Registering
// it before the shared setting stack lets the stack's TryAdd adoption keep the activated snapshot
// visible to IServiceSettingCurrentSnapshotAccessor and ServiceSettingQueryService consumers.
builder.Services.AddSingleton(bootstrapResult.CurrentSnapshotAccessor);

// ---- Shared ServiceMantle setting stack (the runtime snapshot authority since #548) ----
builder.Services.AddSignaCoreSharedSettings(
    SignaCoreBootstrapStore.ToDatabaseOptions(bootstrapResult.Bootstrap.Database),
    builder.Environment.IsDevelopment());

// The authenticated bootstrap editor needs the root secret verbatim so a database change can keep
// the current key without asking the operator to retype it. It is registered as the internal
// bootstrap record rather than as a bare string so nothing else can resolve it by accident.
builder.Services.AddSingleton(bootstrapResult.Bootstrap);
builder.Services.AddSingleton<BootstrapConfigurationService>();

var app = builder.Build();

SignaCoreLogging.WriteLokiWarning(app.Logger, lokiSettings!);
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
        seedScope.ServiceProvider.GetRequiredService<IManagementAuditWriter>(),
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
// UserInfo.md §CORS and transport: the UserInfo endpoint explicitly opts out of the host's
// AdminWeb CORS policy — no CORS evaluation runs for its path, so no Access-Control-* header
// can appear and no preflight is ever usefully answered; the BFF proxy stays the only consumer.
// Every other path keeps the exact named-policy middleware behavior (CorsMiddleware composed
// directly instead of through UseCors so this branch can skip it by path).
app.Use((context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/oauth2/userinfo", StringComparison.Ordinal))
    {
        return next(context);
    }

    var cors = new Microsoft.AspNetCore.Cors.Infrastructure.CorsMiddleware(
        next,
        app.Services.GetRequiredService<Microsoft.AspNetCore.Cors.Infrastructure.ICorsService>(),
        app.Services.GetRequiredService<ILoggerFactory>(),
        "AdminWeb");
    return cors.Invoke(
        context,
        app.Services.GetRequiredService<Microsoft.AspNetCore.Cors.Infrastructure.ICorsPolicyProvider>());
});
// Redaction moves ahead of the composed pipeline: it ran between authentication and authorization
// before, and the gateway schemes still authenticate on demand deeper in the pipeline through
// HttpContextExtensions, which prefers the protected Items copy.
app.UseMiddleware<SensitiveHeaderRedactionMiddleware>();
// The bounded, single form read of Token, Revoke and Logout preparation (the outer input gate): it
// runs after redaction and before the partition resolver so the resolver reuses the cached form
// (or skips every candidate on the fixed failure marker), and the marked request still flows
// through the shared phase and rate-limit budget before its fixed 400/503 answer.
app.UseMiddleware<BoundedOidcFormReadingMiddleware>();
// The interactive OIDC rate-limit partition resolver runs ahead of the composed pipeline: the
// limiter's policy factory is synchronous, so the registered-client resolution for the
// client:{appId} partitions is staged here, cache-first and cancellation-observing (#304).
app.UseMiddleware<OidcClientPartitionResolverMiddleware>();
// The composed ServiceMantle pipeline replaces the individually inserted correlation-id,
// rate-limiting, authentication, and authorization middleware. It must be called exactly once and
// must not be mixed with the individual ServiceMantle entry points.
app.UseServiceMantlePipeline();

// The bootstrap update guard runs after the shared pipeline — so its 401/403 still precede the
// host rules — and before the endpoint: it refuses a Development-fallback host and an
// unconfirmed database change without calling the shared handler, and it owns the
// bootstrap_updated audit row and the controlled stop after a published update.
app.UseMiddleware<BootstrapUpdateGuardMiddleware>();

// The product running-configuration-version header rides only on the shared current-values
// response. It is registered after the shared pipeline so the exact management route it matches is
// the one the shared endpoints serve, and it never touches any other response.
app.UseMiddleware<RunningConfigurationVersionHeaderMiddleware>();

// ---- Health ----
// The shared phase-aware endpoints own all three health routes: liveness answers process-alive
// only, while readiness fail-closes with 503 on any snapshot, database, or signing-key failure.
// Existing launchers and Consul checks keep polling the /health readiness alias.
app.MapServiceMantleHealthEndpoints();

// A completed installation must never re-enter setup. Browser navigation goes to the console; the
// setup entry itself answers the fixed management conflict for a completed installation without
// parsing the request. This is middleware rather than a mapped endpoint because the SPA branch of
// a not-yet-restarted host serves the same path, and the guard has to stay identical between the
// two hosts.
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments(FirstRunPaths.Setup) ||
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

// ---- Shared management settings (definitions / current values / transactional update) ----
// The admin console's settings page rides the shared group from here on: the queries read the
// shared aggregate the runtime itself loads, and the update runs in the executor's own
// single-attempt serializable transaction instead of the legacy controller. The Bootstrap and
// Setup hosts never map this group, so those phases expose no settings surface.
var managementApi = app.MapServiceMantleManagementApiV1();
managementApi.MapServiceMantleSettingQueries();
managementApi.MapServiceMantleSettingUpdates(ManagementSettingUpdateExecutor.ExecuteAsync);
// The admin console's audit page reads the shared restricted query from here on; the legacy
// /api/admin/audit-logs endpoint is gone. The audit_logs table stays as a retained, unwritten
// legacy store for pre-switch history rows.
managementApi.MapServiceMantleAuditQueries();

// ---- Shared setup entries (status read + the completion replay boundary) ----
app.MapServiceMantleSetup(SetupCompletionExecutor.ExecuteAsync);

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
