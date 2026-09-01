using System.Diagnostics.Metrics;

namespace SignaCore.Domain;

public class AuthMetrics
{
    private readonly Counter<int> _loginSuccessCounter;
    private readonly Counter<int> _loginFailureCounter;
    private readonly Histogram<double> _loginDuration;
    private readonly Counter<int> _accountCreationCounter;
    private readonly Counter<int> _oidcAuthorizeCounter;

    public AuthMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create("SignaCore");
        _loginSuccessCounter = meter.CreateCounter<int>("auth.login.success", "count", "Successful login attempts");
        _loginFailureCounter = meter.CreateCounter<int>("auth.login.failure", "count", "Failed login attempts");
        _loginDuration = meter.CreateHistogram<double>("auth.login.duration", "ms", "Login request duration");
        _accountCreationCounter = meter.CreateCounter<int>("auth.account.creation", "count", "Account creation attempts");
        _oidcAuthorizeCounter = meter.CreateCounter<int>("oidc.authorize.validation", "count", "Authorization request validation outcomes");
    }

    public void RecordLoginSuccess(string grantType) => _loginSuccessCounter.Add(1, new KeyValuePair<string, object?>("grant_type", grantType));
    public void RecordLoginFailure(string grantType, string reason) => _loginFailureCounter.Add(1, new KeyValuePair<string, object?>("grant_type", grantType), new KeyValuePair<string, object?>("reason", reason));
    public void RecordLoginDuration(double milliseconds, string grantType) => _loginDuration.Record(milliseconds, new KeyValuePair<string, object?>("grant_type", grantType));
    public void RecordAccountCreation(string source) => _accountCreationCounter.Add(1, new KeyValuePair<string, object?>("source", source));

    /// <summary>
    /// One authorization-request validation outcome. Both labels are bounded on purpose (DF-13):
    /// <paramref name="outcome"/> comes from the closed local-reason and OAuth error-code sets, and
    /// <paramref name="clientId"/> is a registered application id or the fixed
    /// <see cref="UnregisteredClient"/> placeholder. No request value is ever a label, because the
    /// request supplies unbounded attacker-controlled text.
    /// </summary>
    public void RecordOidcAuthorizeOutcome(string outcome, string clientId) =>
        _oidcAuthorizeCounter.Add(
            1,
            new KeyValuePair<string, object?>("outcome", outcome),
            new KeyValuePair<string, object?>("client_id", clientId));

    /// <summary>Metric label used when no registered application was resolved.</summary>
    public const string UnregisteredClient = "unregistered";
}
