using SignaCore.Host.Installation;

namespace SignaCore.Host.Management;

/// <summary>
/// Adds the product header <c>X-SignaCore-Running-Configuration-Version</c> to the successful
/// current-values response of the shared management setting query — and to nothing else.
/// </summary>
/// <remarks>
/// The running version is what this process activated at bootstrap; the shared response body
/// carries the version of the snapshot the request just refreshed, which is not the same thing and
/// must not be derived from a refreshed accessor. The header is a product add-on on the SignaCore
/// side: the shared JSON stays untouched, the header is not added to any other endpoint (including
/// the definitions query), and it describes only the instance that answered the request — it makes
/// no claim about the rest of a cluster. A missing or unparseable header therefore means "running
/// version unknown" to the console, never "the running version matches".
/// </remarks>
internal sealed class RunningConfigurationVersionHeaderMiddleware(
    RequestDelegate next,
    InstallationRuntimeState runtimeState)
{
    internal const string HeaderName = "X-SignaCore-Running-Configuration-Version";

    // The exact current-values route of the shared management API v1 group at its fixed root.
    private const string CurrentValuesPath = "/management/v1/settings";

    public async Task InvokeAsync(HttpContext context)
    {
        if (HttpMethods.IsGet(context.Request.Method) &&
            context.Request.Path.Equals(CurrentValuesPath, StringComparison.Ordinal))
        {
            context.Response.OnStarting(() =>
            {
                if (context.Response.StatusCode == StatusCodes.Status200OK)
                {
                    context.Response.Headers[HeaderName] =
                        runtimeState.ConfigurationVersion.ToString(System.Globalization.CultureInfo.InvariantCulture);
                }

                return Task.CompletedTask;
            });
        }

        await next(context);
    }
}
