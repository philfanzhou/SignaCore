using System.Text.Json;
using ServiceMantle.Configuration;
using SignaCore.Domain.Services.Sms;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Validates the SMS bypass allow-list at every save entry point (the management settings API,
/// first-run setup, and legacy configuration import). The list turns an OTP bypass code into a
/// complete login, so a mistyped phone number stored here is silent until someone logs in with it;
/// each entry must therefore normalize as a mainland China mobile number before it can be stored.
/// The rule mirrors the login path (<see cref="Domain.Services.Sms"/> validators normalize both the
/// configured entries and the request phone before matching), while the entry cap follows the
/// allow-list sizing precedent of <c>IdentityConstants.MaxOidcRedirectUrisPerKind</c>.
/// </summary>
/// <remarks>
/// Stored entries are intentionally not rewritten to the normalized form: matching normalizes both
/// sides, so <c>13800138000</c> and <c>+8613800138000</c> stay equivalent at runtime. Values that
/// reach the running process through the environment or Consul do not pass a save entry point and
/// remain the operator's responsibility, as before.
/// </remarks>
internal sealed class SmsBypassPhonesSettingConstraint : IServiceSettingValueConstraint
{
    internal const string SettingKey = "sms.bypass_phones";

    /// <summary>The maximum number of allow-list entries accepted at save time.</summary>
    internal const int MaxEntries = 100;

    public ServiceSettingValueType ValueType => ServiceSettingValueType.Json;

    public string ErrorCode => ServiceSettingDefinitions.SmsBypassPhoneInvalidErrorCode;

    public bool IsSatisfied(ServiceSettingValue value)
    {
        var json = value.GetJson();
        // The root-kind constraint owns the array shape; guard the enumeration here so a different
        // root kind reports the closed constraint failure instead of throwing.
        if (json.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        var count = 0;
        foreach (var item in json.EnumerateArray())
        {
            count++;
            if (count > MaxEntries)
            {
                return false;
            }

            if (item.ValueKind != JsonValueKind.String ||
                !MainlandChinaPhoneNumber.TryNormalize(item.GetString(), out _))
            {
                return false;
            }
        }

        return true;
    }
}
