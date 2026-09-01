using System.Diagnostics.CodeAnalysis;
using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services;

public class GatewayAuthResult
{
    /// <summary>
    /// Whether gateway validation passed.
    /// <para>
    /// <see cref="MemberNotNullWhenAttribute"/> hands the invariant "a failure always carries a
    /// reason" to the compiler: the parameter of <see cref="Failure"/> is a non-nullable
    /// <see cref="string"/>, and an instance can only be produced by the two factory methods below
    /// (every property is private set, so nothing outside can construct one). Therefore
    /// <see cref="ErrorMessage"/> is necessarily non-null inside an
    /// <c>if (!result.IsSuccess)</c> branch.
    /// </para>
    /// <para>
    /// Without this annotation each call site has to reach for <c>!</c> or
    /// <c>?? "some fallback text"</c> of its own — one invariant once had four different spellings
    /// across four places, and the one that was forgotten left a nullable warning behind.
    /// </para>
    /// </summary>
    [MemberNotNullWhen(false, nameof(ErrorMessage))]
    public bool IsSuccess { get; private set; }

    public string? ErrorMessage { get; private set; }

    public AppRegistrationEntity? App { get; private set; }

    public static GatewayAuthResult Success(AppRegistrationEntity? app = null) => new()
    {
        IsSuccess = true,
        App = app
    };

    public static GatewayAuthResult Failure(string message) => new()
    {
        IsSuccess = false,
        ErrorMessage = message
    };
}
