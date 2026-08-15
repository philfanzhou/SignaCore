using Microsoft.AspNetCore.Mvc.ApplicationModels;
using SignaCore.Host.Controllers;

namespace SignaCore.Host.Startup;

/// <summary>
/// Narrows Setup Mode's MVC surface to the two controllers first-run setup actually needs.
/// <para>
/// MVC discovers controllers from the assembly, so without this every controller is routed while
/// installation is pending. A request that matches one of them — <c>POST /api/auth/token</c>, say —
/// resolves an endpoint carrying <c>[Authorize(Policy = "GatewayApp")]</c>, and because Setup Mode
/// deliberately never registers that policy the authorization middleware throws and the caller sees
/// a 500. Dropping the actions means nothing matches and
/// <see cref="Middleware.SetupModeGateMiddleware"/> answers <c>503 installation_required</c> as
/// designed. It also keeps requests away from controllers whose dependencies Setup Mode does not
/// compose at all.
/// </para>
/// </summary>
internal sealed class SetupModeControllerConvention : IApplicationModelConvention
{
    private static readonly HashSet<Type> Allowed =
    [
        typeof(SetupController),
        typeof(BootstrapController)
    ];

    public void Apply(ApplicationModel application)
    {
        for (var index = application.Controllers.Count - 1; index >= 0; index--)
        {
            if (!Allowed.Contains(application.Controllers[index].ControllerType.AsType()))
            {
                application.Controllers.RemoveAt(index);
            }
        }
    }
}
