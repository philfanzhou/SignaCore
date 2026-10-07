using Microsoft.AspNetCore.Http;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The configuration of the hosted-login integration. The protocol settings (Authority, client
/// registration, redirect URI) are validated at startup: a missing or illegal value is a startup
/// failure whose diagnostics name the option, never the value.
/// </summary>
public sealed class SignaCoreHostedLoginOptions
{
    /// <summary>
    /// The SignaCore base address, for example <c>https://signacore.example</c>. Must be an
    /// absolute HTTPS URI without a path, query, or fragment; only the Development and Testing
    /// environments additionally accept an explicit loopback origin
    /// (<c>http://127.0.0.1</c> or <c>http://[::1]</c>). The package verifies the Discovery
    /// document's <c>issuer</c> against this value.
    /// </summary>
    public string? Authority { get; set; }

    /// <summary>The registered application id (the SignaCore <c>appId</c>).</summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// The registered application secret of the Confidential client. It is used only as HTTP Basic
    /// authentication on the server-to-server token request and never reaches the browser.
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// The exact, pre-registered callback URI, for example
    /// <c>https://orders.example/bff/callback</c>. Must be an absolute HTTPS URI whose path is
    /// byte-for-byte the callback path of the mapped prefix
    /// (<see cref="M:SignaCore.Client.AspNetCore.SignaCoreHostedLoginEndpointExtensions.MapSignaCoreHostedLogin(Microsoft.AspNetCore.Routing.IEndpointRouteBuilder,string)"/>).
    /// </summary>
    public string? RedirectUri { get; set; }

    /// <summary>
    /// The requested scopes. Always includes <c>openid</c>; add <c>profile</c> to receive the
    /// display name. Refresh tokens are not supported by this package in the first phase.
    /// </summary>
    public string Scope { get; set; } = "openid profile";

    /// <summary>The name of the opaque session cookie. The default is
    /// <see cref="SignaCoreHostedLoginDefaults.SessionCookieName"/>.</summary>
    public string SessionCookieName { get; set; } = SignaCoreHostedLoginDefaults.SessionCookieName;

    /// <summary>
    /// The maximum number of concurrent server-side session tickets the default in-memory store
    /// holds. When the store is full a new sign-in fails closed with the bounded
    /// <c>session_store_full</c> reason; nothing of an existing session is evicted. Consumers with
    /// more traffic replace the store through their own <see cref="ITicketStore"/> registration.
    /// </summary>
    public int TicketCapacity { get; set; } = 10_000;

    /// <summary>
    /// Extension point — authorization decision. Called with the principal verified from the ID
    /// token; the consumer decides what that subject may do (typically by matching the verified
    /// issuer plus <c>sub</c> against its own bindings). The result is reported by the session
    /// endpoint; the package itself enforces no business rule. Default: allow every subject.
    /// </summary>
    public ISignaCoreAuthorizationDecision AuthorizationDecision { get; set; } =
        SignaCoreAllowAllAuthorizationDecision.Instance;

    /// <summary>
    /// Optional authorization before callback sign-in. Default null preserves the ID-token-only
    /// path. When configured, strictly validates and correlates the SignaCore access token too.
    /// Only timely Allowed writes a new session; failures leave existing sessions unchanged.
    /// </summary>
    public ISignaCorePreSignInAuthorizationDecision? PreSignInAuthorizationDecision { get; set; }

    /// <summary>
    /// Maximum asynchronous decision wait. Default ten seconds; must be positive and at most
    /// thirty seconds. Timeout cancels the decision token and fails closed with access_denied.
    /// </summary>
    public TimeSpan PreSignInAuthorizationTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Extension point — response format. Owns the bodies and status codes of the consumer-facing
    /// routes (the failure redirect target and the session-status answer). The package defines the
    /// protocol outcomes; this writer defines their presentation. Default: a fixed English failure
    /// page and a fixed JSON session body.
    /// </summary>
    public ISignaCoreHostedLoginResponseWriter ResponseWriter { get; set; } =
        SignaCoreDefaultResponseWriter.Instance;

    /// <summary>
    /// Extension point — session and Bearer scheme selection. Returns, per request, the
    /// authentication scheme that serves it: the package's session scheme
    /// (<see cref="SignaCoreHostedLoginDefaults.SessionAuthenticationScheme"/>) or a host-owned
    /// scheme such as its Bearer handler. Return <see langword="null"/> to keep the session
    /// scheme. Default: every request authenticates against the package's session.
    /// </summary>
    public Func<HttpContext, string?>? SchemeSelector { get; set; }

    /// <summary>
    /// The request-header name the antiforgery validation accepts. Every session-authenticated
    /// unsafe method (anything but GET, HEAD, OPTIONS, and TRACE) must present the token from
    /// <c>GET &lt;prefix&gt;/csrf</c> in this header; a missing or wrong token fails the request.
    /// Requests forwarded by <see cref="SchemeSelector"/> to a host scheme are unaffected. The
    /// default is <see cref="SignaCoreHostedLoginDefaults.AntiforgeryHeaderName"/>; the value is
    /// applied to the shared antiforgery configuration, and an application that post-configures
    /// <c>AntiforgeryOptions</c> after <c>AddSignaCoreHostedLogin</c> can still override it.
    /// </summary>
    public string AntiforgeryHeaderName { get; set; } = SignaCoreHostedLoginDefaults.AntiforgeryHeaderName;

    /// <summary>
    /// The consumer's post-logout redirect URI, exactly as registered in SignaCore with the
    /// <c>PostLogout</c> kind. Its path must be exactly <c>&lt;prefix&gt;/logout/return</c>. When
    /// set, the logout endpoint passes it to the prepared-logout request and SignaCore returns the
    /// browser to that endpoint after finishing; when <see langword="null"/>, SignaCore shows its
    /// own signed-out page instead of redirecting back.
    /// </summary>
    public string? PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// The fixed local path the logout-return endpoint redirects the browser to after a completed
    /// prepared logout. Must be a local absolute path (it starts with exactly one slash). The
    /// default is <c>/</c>.
    /// </summary>
    public string PostLogoutReturnPath { get; set; } = "/";

    /// <summary>The route prefix the endpoints are mapped under; set by
    /// <c>MapSignaCoreHostedLogin</c>, not by consumer code.</summary>
    public string? Prefix { get; internal set; }

    /// <summary>
    /// Allows the host to start with the protocol options (Authority, ClientId, ClientSecret,
    /// RedirectUri) left blank: optional sign-in mode. Default false keeps the historical
    /// behavior — a missing required option fails startup. When true, a blank required option
    /// starts the host and the sign-in surface degrades to a fixed 503 (the session endpoint
    /// answers the anonymous expired status, logout is local-only, and CSRF tokens are issued
    /// as usual); a configured but illegal value still fails startup — half-configuration is an
    /// error, never a silent downgrade. The mode does not hot-reload: configuring the values
    /// requires a restart, consistent with the protocol-settings consistency requirement.
    /// </summary>
    public bool AllowUnconfiguredStartup { get; set; }

    /// <summary>
    /// The validation strictness policy of the ID-token, access-token, and backchannel response
    /// checks. The defaults are the strict profile (zero clock skew, scope-echo subset check,
    /// duplicate JSON members rejected, bounded response bodies, future <c>iat</c> rejected);
    /// every dimension can be relaxed independently through this group.
    /// </summary>
    public SignaCoreValidationOptions Validation { get; set; } = new();

    /// <summary>
    /// Whether the session-status endpoint requires an authenticated user (endpoint
    /// authorization). Default false keeps the endpoint anonymous — anyone may learn whether the
    /// browser holds a live session, exactly as before. When true, an unauthenticated request is
    /// rejected by the host's authorization pipeline before the endpoint runs: the challenge is
    /// the host's to present (with the package's scheme as the host default it is a 302 to the
    /// sign-in start; a 401 JSON envelope is a policy-scheme or writer combination of the
    /// consumer's). Only this endpoint gains the requirement; start, callback, csrf, logout, and
    /// the failure page stay as they are.
    /// </summary>
    public bool SessionEndpointRequireAuthorization { get; set; }
}
