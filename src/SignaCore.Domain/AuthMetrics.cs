using System.Diagnostics.Metrics;

namespace SignaCore.Domain;

public class AuthMetrics
{
    private readonly Counter<int> _loginSuccessCounter;
    private readonly Counter<int> _loginFailureCounter;
    private readonly Histogram<double> _loginDuration;
    private readonly Counter<int> _accountCreationCounter;
    private readonly Counter<int> _oidcAuthorizeCounter;
    private readonly Counter<int> _oidcEndpointOutcomeCounter;
    private readonly Histogram<double> _oidcEndpointDuration;

    public AuthMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create("SignaCore");
        _loginSuccessCounter = meter.CreateCounter<int>("auth.login.success", "count", "Successful login attempts");
        _loginFailureCounter = meter.CreateCounter<int>("auth.login.failure", "count", "Failed login attempts");
        _loginDuration = meter.CreateHistogram<double>("auth.login.duration", "ms", "Login request duration");
        _accountCreationCounter = meter.CreateCounter<int>("auth.account.creation", "count", "Account creation attempts");
        _oidcAuthorizeCounter = meter.CreateCounter<int>("oidc.authorize.validation", "count", "Authorization request validation outcomes");
        _oidcEndpointOutcomeCounter = meter.CreateCounter<int>(
            "oidc.endpoint.outcome", "count", "Interactive OIDC endpoint class outcomes");
        _oidcEndpointDuration = meter.CreateHistogram<double>(
            "oidc.endpoint.duration", "ms", "Interactive OIDC endpoint class durations");
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

    /// <summary>
    /// The fixed endpoint-class label values of <c>oidc.endpoint.outcome</c> and
    /// <c>oidc.endpoint.duration</c>: closed set, no free text.
    /// </summary>
    public static class OidcMetricEndpoints
    {
        /// <summary>The code-redemption and legacy-grant half of <c>POST /oauth2/token</c>.</summary>
        public const string Token = "token";

        /// <summary>The interactive refresh half of <c>POST /oauth2/token</c>.</summary>
        public const string Refresh = "refresh";

        public const string UserInfo = "userinfo";
        public const string LogoutPrepare = "logout-prepare";
        public const string LogoutComplete = "logout-complete";
    }

    /// <summary>
    /// The outcome value reserved for the rate-limit rejection of an interactive endpoint class.
    /// The value and the endpoint dimension are defined here; the counting itself is wired by the
    /// limiter delivery — this class keeps no dependency on it.
    /// </summary>
    public const string RateLimitedOutcome = "rate_limited";

    /// <summary>
    /// One interactive endpoint-class outcome. Every label is bounded (DF-11/DF-13):
    /// <paramref name="endpoint"/> comes from <see cref="OidcMetricEndpoints"/>,
    /// <paramref name="outcome"/> from the closed service failure-reason and OAuth error-code
    /// sets — replay/reuse and the transaction-rollback <c>server_error</c> are distinct values —
    /// and <paramref name="clientId"/>, when supplied, is a registered application id. Recording
    /// failures are swallowed: observability never changes the protocol result.
    /// </summary>
    public void RecordOidcEndpointOutcome(string endpoint, string outcome, string? clientId = null)
    {
        try
        {
            RecordOidcEndpointOutcomeCore(endpoint, outcome, clientId);
        }
        catch (Exception)
        {
            // Observability must never change the protocol result — whatever a subclass or the
            // instrument pipeline throws, the protocol answer is already decided.
        }
    }

    /// <summary>The recording seam: overridden by tests to simulate instrument failures.</summary>
    protected virtual void RecordOidcEndpointOutcomeCore(string endpoint, string outcome, string? clientId)
    {
        KeyValuePair<string, object?>[] tags = clientId is null
            ? [new("endpoint", endpoint), new("outcome", outcome)]
            : [new("endpoint", endpoint), new("outcome", outcome), new("client_id", clientId)];
        _oidcEndpointOutcomeCounter.Add(1, tags);
    }

    /// <summary>
    /// One interactive endpoint-class latency observation. Failures are swallowed: observability
    /// never changes the protocol result.
    /// </summary>
    public void RecordOidcEndpointDuration(string endpoint, double milliseconds)
    {
        try
        {
            RecordOidcEndpointDurationCore(endpoint, milliseconds);
        }
        catch (Exception)
        {
            // Observability must never change the protocol result.
        }
    }

    /// <summary>The recording seam: overridden by tests to simulate instrument failures.</summary>
    protected virtual void RecordOidcEndpointDurationCore(string endpoint, double milliseconds) =>
        _oidcEndpointDuration.Record(
            milliseconds,
            new KeyValuePair<string, object?>("endpoint", endpoint));
}
