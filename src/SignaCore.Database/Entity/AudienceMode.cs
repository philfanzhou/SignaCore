namespace SignaCore.Database.Entity;

/// <summary>
/// Which value goes into the <c>aud</c> claim of access tokens issued to this application.
/// <para>
/// <see cref="Shared"/> is the historical behaviour: every application receives the single configured
/// <c>Jwt:Audience</c>, which means an access token minted for one application also validates at every
/// other one — the audience is not a boundary. <see cref="PerApplication"/> puts the application's own
/// AppId in <c>aud</c>, making it one.
/// </para>
/// <para>
/// The mode is per application on purpose. A downstream service validates the audience with its own
/// configuration, so a global switch would force every consumer to cut over in the same deployment
/// window. Per application, the rollout is:配置下游同时接受两个 audience → flip this mode → drop the
/// shared value downstream.
/// </para>
/// </summary>
public enum AudienceMode
{
    Shared = 0,
    PerApplication = 1
}
