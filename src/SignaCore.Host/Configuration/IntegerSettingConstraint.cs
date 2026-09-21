using System.Globalization;
using ServiceMantle.Configuration;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Keeps the legacy integer semantics for Number settings: the shared contract parses Number as an
/// invariant decimal, while every SignaCore Number key has always been an integer.
/// <see cref="SettingCandidateValidation"/> enforces the same integer text form through
/// <see cref="IsIntegerText"/> on complete candidates before the registry parses the value.
/// </summary>
internal sealed class IntegerSettingConstraint : IServiceSettingValueConstraint
{
    public ServiceSettingValueType ValueType => ServiceSettingValueType.Number;

    public string ErrorCode => ServiceSettingDefinitions.IntegerErrorCode;

    public bool IsSatisfied(ServiceSettingValue value)
    {
        var number = value.GetNumber();
        return number == Math.Truncate(number) &&
               number >= long.MinValue &&
               number <= long.MaxValue;
    }

    internal static bool IsIntegerText(string candidate) =>
        long.TryParse(candidate, NumberStyles.Integer, CultureInfo.InvariantCulture, out _);
}
