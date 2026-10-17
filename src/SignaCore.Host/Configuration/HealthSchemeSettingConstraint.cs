using ServiceMantle.Configuration;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Keeps the advertised health URL scheme of <c>consul.discovery.health_scheme</c> on the two
/// documented literals: the value becomes the scheme of the health-check URL the Consul agent
/// polls, so anything other than a plain <c>http</c> or <c>https</c> (compared ordinally, exactly
/// the documented form) is refused at every save entry point instead of failing a registration
/// after the next restart.
/// </summary>
internal sealed class HealthSchemeSettingConstraint : IServiceSettingValueConstraint
{
    internal const string SettingKey = "consul.discovery.health_scheme";

    internal const string Http = "http";
    internal const string Https = "https";

    public ServiceSettingValueType ValueType => ServiceSettingValueType.String;

    public string ErrorCode => ServiceSettingDefinitions.HealthSchemeInvalidErrorCode;

    public bool IsSatisfied(ServiceSettingValue value) =>
        value.GetString() is Http or Https;
}
