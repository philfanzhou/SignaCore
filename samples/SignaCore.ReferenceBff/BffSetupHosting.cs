using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.Relational.Stores;
using ServiceMantle.Web.Health;
using SignaCore.ReferenceBff.Database;
using System.Net;

namespace SignaCore.ReferenceBff;

internal static class BffSetupHosting
{
    internal const string CsrfHeader = "X-ReferenceBff-CSRF";

    internal static void AddSetup(IServiceCollection services)
    {
        services.AddReferenceBffServiceMantleStores();
        services.AddScoped<IServiceSetupCodeStore, EfCoreServiceSetupCodeStore<ReferenceBffDbContext>>();
        services.AddScoped<IServiceHealthSnapshotSource, BffInstallationSnapshot>();
        var mantle = BffLogging.AddServices(services);
        mantle.AddServiceMantleManagementApiV1();
        mantle.AddServiceMantleManagementEntries();
        mantle.AddSecurityResponseHeaders();
        mantle.AddSensitiveHeaders(options => options.DeniedHeaderNames = [CsrfHeader]);
        mantle.AddRateLimiting();
        // API v1 registers the matching phase gate on /management/v1.
    }

    internal static IResult Form(HttpContext http, IAntiforgery antiforgery)
    {
        if (http.User.Identity?.IsAuthenticated != true)
            return Results.Challenge(new AuthenticationProperties { RedirectUri = "/bff/setup" });
        http.Response.Headers.CacheControl = "no-store";
        var token = WebUtility.HtmlEncode(BffAntiforgery.Issue(http, antiforgery).RequestToken);
        return Results.Content($$"""
            <!doctype html><html lang="en"><head><title>Set up administrator</title></head><body>
            <h1>Set up administrator</h1>
            <p>Bind your current sign-in as this BFF's first administrator.</p>
            <form id="setup"><label>Setup code <input id="code" type="password" autocomplete="off" required /></label>
            <input id="csrf" type="hidden" value="{{token}}" />
            <button type="submit">Complete setup</button></form><p id="result" role="status"></p>
            <script>
            document.getElementById('setup').addEventListener('submit', async event => {
                event.preventDefault();
                const code = document.getElementById('code');
                try {
                    const response = await fetch('/management/v1/setup', {
                        method: 'POST', credentials: 'same-origin',
                        headers: {'Content-Type': 'application/json', 'X-ServiceMantle-Request': '1',
                            'X-ReferenceBff-CSRF': document.getElementById('csrf').value},
                        body: JSON.stringify({code: code.value})
                    });
                    document.getElementById('result').textContent = response.status === 204
                        ? 'Setup completed.' : 'Setup did not complete. Check installation status before retrying.';
                } catch {
                    document.getElementById('result').textContent = 'Setup result unavailable. Check installation status before retrying.';
                } finally { code.value = ''; }
            });
            </script></body></html>
            """, "text/html");
    }

    private sealed class BffInstallationSnapshot(IServiceInstallationStore installations) : IServiceHealthSnapshotSource
    {
        public async ValueTask<ServiceHealthSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var state = await installations.FindAsync(ReferenceBffServiceMantle.ServiceId, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                if (state is not null) return new ServiceHealthSnapshot(
                    state.IsCompleted ? ServiceStartupPhase.Completed : ServiceStartupPhase.PendingSetup,
                    ServiceMigrationReadinessState.Succeeded, ServiceDatabaseReadinessState.Reachable);
            }
            catch { cancellationToken.ThrowIfCancellationRequested(); }
            // Failed migration readiness prevents phase-only admission from bypassing an absent
            // or corrupt installation authority. This source never initializes or migrates.
            return new ServiceHealthSnapshot(ServiceStartupPhase.PendingSetup,
                ServiceMigrationReadinessState.Failed, ServiceDatabaseReadinessState.Unreachable);
        }
    }
}
