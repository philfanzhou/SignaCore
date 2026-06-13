using System.Diagnostics.Metrics;

namespace QuantumZhou.Identity.Domain;

public class AuthMetrics
{
    private readonly Counter<int> _loginSuccessCounter;
    private readonly Counter<int> _loginFailureCounter;
    private readonly Histogram<double> _loginDuration;
    private readonly Counter<int> _accountCreationCounter;

    public AuthMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create("QuantumZhou.Identity");
        _loginSuccessCounter = meter.CreateCounter<int>("auth.login.success", "count", "Successful login attempts");
        _loginFailureCounter = meter.CreateCounter<int>("auth.login.failure", "count", "Failed login attempts");
        _loginDuration = meter.CreateHistogram<double>("auth.login.duration", "ms", "Login request duration");
        _accountCreationCounter = meter.CreateCounter<int>("auth.account.creation", "count", "Account creation attempts");
    }

    public void RecordLoginSuccess(string grantType) => _loginSuccessCounter.Add(1, new KeyValuePair<string, object?>("grant_type", grantType));
    public void RecordLoginFailure(string grantType, string reason) => _loginFailureCounter.Add(1, new KeyValuePair<string, object?>("grant_type", grantType), new KeyValuePair<string, object?>("reason", reason));
    public void RecordLoginDuration(double milliseconds, string grantType) => _loginDuration.Record(milliseconds, new KeyValuePair<string, object?>("grant_type", grantType));
    public void RecordAccountCreation(string source) => _accountCreationCounter.Add(1, new KeyValuePair<string, object?>("source", source));
}
