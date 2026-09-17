using System.Text;
using SignaCore.Host.Http;
using Xunit;

namespace SignaCore.Tests.Host.Http;

/// <summary>
/// The <c>EV-01</c> success redirect construction (<c>PS-17</c>): the exact registered URI, the
/// fixed parameter order <c>code</c>, <c>state</c>, <c>iss</c>, the shared separator rule with
/// <see cref="OidcAuthorizationRedirect.BuildError"/> ('&amp;' when the registered URI already
/// carries a query), and the shared escaping — a byte-for-byte echo of the <c>IN-05</c> state and
/// of the unreserved-alphabet code.
/// </summary>
public sealed class OidcAuthorizationRedirectTests
{
    private const string Code = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string State = "redirect-state-0123456789abcdef";
    private const string Issuer = "https://issuer.example";

    [Theory]
    [InlineData("https://client.example.com/callback")]
    [InlineData("https://client.example.com/cb?tenant=blue")]
    public void BuildSuccess_MatchesTheContractReferenceConstructionByteForByte(
        string registeredRedirectUri)
    {
        // The reference implementation is the PS-17 construction spelled out in the canonical
        // model, inlined here so the shared builder cannot drift a single byte.
        var separator = registeredRedirectUri.Contains('?', StringComparison.Ordinal)
            ? '&'
            : '?';
        var reference = new StringBuilder(registeredRedirectUri);
        reference.Append(separator);
        Append(reference, "code", Code, first: true);
        Append(reference, "state", State, first: false);
        Append(reference, "iss", Issuer, first: false);

        Assert.Equal(
            reference.ToString(),
            OidcAuthorizationRedirect.BuildSuccess(registeredRedirectUri, Code, State, Issuer));

        static void Append(StringBuilder builder, string name, string value, bool first)
        {
            if (!first)
            {
                builder.Append('&');
            }

            builder.Append(name).Append('=').Append(Uri.EscapeDataString(value));
        }
    }

    [Fact]
    public void BuildSuccess_KeepsTheFixedParameterOrderAndTheStoredQuery()
    {
        var location = OidcAuthorizationRedirect.BuildSuccess(
            "https://client.example.com/cb?tenant=blue", Code, State, Issuer);

        Assert.Equal(
            "https://client.example.com/cb?tenant=blue"
            + "&code=" + Code
            + "&state=" + State
            + "&iss=" + Uri.EscapeDataString(Issuer),
            location);
    }

    [Fact]
    public void BuildSuccess_JoinsWithTheQuestionMarkWhenTheUriHasNoQuery()
    {
        var location = OidcAuthorizationRedirect.BuildSuccess(
            "https://client.example.com/callback", Code, State, Issuer);

        Assert.StartsWith(
            "https://client.example.com/callback?code=", location, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildSuccess_ThrowsOnANullRedirectUri()
    {
        Assert.Throws<ArgumentNullException>(() =>
            OidcAuthorizationRedirect.BuildSuccess(null!, Code, State, Issuer));
    }
}
