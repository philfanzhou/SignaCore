using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Primitives;
using SignaCore.Host.Http;

namespace SignaCore.Host.Security;

/// <summary>
/// The outcome of the outer bounded form read for the two standard form endpoints.
/// </summary>
public enum OidcBoundedFormStatus
{
    /// <summary>The body was read within the bound and parsed; the form is cached on the request.</summary>
    Parsed = 1,

    /// <summary>
    /// The request exceeded the read bound, was not a plain UTF-8 form, or carried malformed
    /// percent/UTF-8 encoding. No error text, no input value, and no marker payload is retained.
    /// </summary>
    Malformed = 2,

    /// <summary>
    /// The body could not be read (an ordinary I/O failure or an internal cancellation) while the
    /// caller is still waiting. Again, no diagnostic detail is retained.
    /// </summary>
    Unavailable = 3
}

/// <summary>
/// The single bounded, strict form read for <c>POST /oauth2/token</c> and <c>POST /oauth2/revoke</c>
/// (the outer input gate of the shared protocol model). Exactly one read of at most 16385 raw
/// bytes happens here, ahead of the partition resolver and the composed pipeline; a successful
/// parse is installed as the request's <c>IFormFeature</c> so every downstream
/// <c>Request.Form</c>/<c>ReadFormAsync</c> reuses it, and a failed read leaves only the fixed
/// marker so later stages neither re-read the stream nor query client rows.
/// <para>
/// The bound is enforced on the bytes actually read, never on the client-declared Content-Length:
/// reading stops at one byte past the 16384-byte limit, so a lying or absent length cannot smuggle
/// a larger body. Media type must be <c>application/x-www-form-urlencoded</c> with, at most, a
/// <c>charset=utf-8</c> parameter; compressed bodies are not accepted. Decoding is one strict
/// UTF-8 pass with a single percent-decode (<c>+</c> is a space; percent hex is case-insensitive;
/// <c>=</c> after the first is value bytes). Duplicate fields keep their
/// <see cref="StringValues"/> cardinality for the existing grant field rules; unknown fields are
/// preserved and stay ignored by the grants, exactly as before.
/// </para>
/// <para>
/// This gate never writes a response itself: a marked request continues through the pipeline so
/// the shared phase and rate-limit budget still admit it first, and the fixed 400/503 answers are
/// produced by the client-authentication challenge that owns those endpoints' error surface. The
/// raw buffer is zeroed after parsing; no request value is ever logged or surfaced by this class.
/// </para>
/// </summary>
public sealed class BoundedOidcFormReadingMiddleware(RequestDelegate next)
{
    /// <summary>The <c>HttpContext.Items</c> key carrying the gate's fixed outcome marker.</summary>
    public const string StatusItemKey = "signacore.oidc.bounded-form.status";

    /// <summary>The canonical bound of the request form body shared by the standard endpoints.</summary>
    internal const int MaxFormBytes = 16 * 1024;

    /// <summary>The read stops at one byte past the bound so oversize is recognizable by count.</summary>
    internal const int MaxReadBytes = MaxFormBytes + 1;

    private const string FormUrlEncodedContentType = "application/x-www-form-urlencoded";
    private const string CharsetParameterName = "charset";
    private const string Utf8Charset = "utf-8";

    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public async Task InvokeAsync(HttpContext context)
    {
        if (HttpMethods.IsPost(context.Request.Method) && IsGatedPath(context.Request.Path))
        {
            await ReadAndMarkAsync(context);
        }

        await next(context);
    }

    /// <summary>
    /// Whether this path is one of the two endpoints this gate owns. Routing matches literal
    /// segments case-insensitively, and the comparison here tolerates a trailing slash, so no
    /// casing or trailing-slash variant can slip past the gate into a routable shape.
    /// </summary>
    internal static bool IsGatedPath(PathString path)
    {
        var value = path.Value ?? string.Empty;
        if (value.Length > 0 && value[^1] == '/')
        {
            value = value[..^1];
        }

        return string.Equals(value, "/oauth2/token", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "/oauth2/revoke", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The gate's outcome for this request, or null when the gate did not run.</summary>
    public static OidcBoundedFormStatus? GetStatus(HttpContext context) =>
        context.Items.TryGetValue(StatusItemKey, out var status) && status is OidcBoundedFormStatus bounded
            ? bounded
            : null;

    /// <summary>Whether the fixed failure marker is present: later stages must not read anything.</summary>
    public static bool IsFailed(HttpContext context) =>
        GetStatus(context) is OidcBoundedFormStatus.Malformed or OidcBoundedFormStatus.Unavailable;

    private async Task ReadAndMarkAsync(HttpContext context)
    {
        try
        {
            var status = await TryReadAndInstallFormAsync(context);
            context.Items[StatusItemKey] = status;
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            // The caller abandoned the request: nothing is marked, staged, or answered here.
            throw;
        }
        catch (OperationCanceledException)
        {
            // An internal cancellation while the caller still waits.
            context.Items[StatusItemKey] = OidcBoundedFormStatus.Unavailable;
        }
        catch (IOException)
        {
            context.Items[StatusItemKey] = OidcBoundedFormStatus.Unavailable;
        }
    }

    private async Task<OidcBoundedFormStatus> TryReadAndInstallFormAsync(HttpContext context)
    {
        // Compressed or non-form media, or a charset other than UTF-8: the request never gets a
        // body read, and no later stage may fall back to the framework form reader.
        if (!IsAdmittedFormContentType(context.Request.ContentType)
            || context.Request.Headers.ContainsKey("Content-Encoding"))
        {
            return OidcBoundedFormStatus.Malformed;
        }

        // Reading stops at one byte past the bound: oversize is recognized by the byte count, so
        // the declared Content-Length is irrelevant and nothing beyond the cap is ever consumed.
        var buffer = new byte[MaxReadBytes];
        var total = 0;
        while (total < MaxReadBytes)
        {
            var read = await context.Request.Body.ReadAsync(
                buffer.AsMemory(total, MaxReadBytes - total),
                context.RequestAborted);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        if (total == MaxReadBytes)
        {
            Array.Clear(buffer);
            return OidcBoundedFormStatus.Malformed;
        }

        if (!TryParseStrictForm(buffer.AsSpan(0, total), out var fields))
        {
            Array.Clear(buffer);
            return OidcBoundedFormStatus.Malformed;
        }

        Array.Clear(buffer);
        // The one parse is the only parse: downstream Request.Form/ReadFormAsync reuse it.
        context.Features.Set<IFormFeature>(new FormFeature(new FormCollection(fields)));
        return OidcBoundedFormStatus.Parsed;
    }

    /// <summary>
    /// One strict UTF-8, single-percent-decode parse of an <c>x-www-form-urlencoded</c> body.
    /// Segments split on <c>&amp;</c> (empty segments are skipped, as the framework reader does);
    /// the first <c>=</c> separates name from value, later <c>=</c> bytes belong to the value, and
    /// a segment without <c>=</c> is a name with an empty value. Duplicate names keep their
    /// cardinality; unknown names are kept and remain the grants' business to ignore.
    /// </summary>
    internal static bool TryParseStrictForm(ReadOnlySpan<byte> body, out Dictionary<string, StringValues> fields)
    {
        var pending = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        if (!body.IsEmpty)
        {
            var start = 0;
            while (start < body.Length)
            {
                var remainder = body[start..];
                var separator = remainder.IndexOf((byte)'&');
                var end = separator >= 0 ? start + separator : body.Length;
                var segment = body[start..end];
                if (!segment.IsEmpty)
                {
                    var equals = segment.IndexOf((byte)'=');
                    var nameSpan = equals >= 0 ? segment[..equals] : segment;
                    var valueSpan = equals >= 0 ? segment[(equals + 1)..] : ReadOnlySpan<byte>.Empty;
                    if (!TryDecodeComponent(nameSpan, out var name)
                        || !TryDecodeComponent(valueSpan, out var value))
                    {
                        fields = new Dictionary<string, StringValues>(0);
                        return false;
                    }

                    if (!pending.TryGetValue(name, out var values))
                    {
                        pending[name] = values = [];
                    }

                    values.Add(value);
                }

                if (separator < 0)
                {
                    break;
                }

                start = end + 1;
            }
        }

        fields = new Dictionary<string, StringValues>(pending.Count, StringComparer.Ordinal);
        foreach (var (name, values)
                 in pending.Select(pair => (pair.Key, new StringValues(pair.Value.ToArray()))))
        {
            fields[name] = values;
        }

        return true;
    }

    private static bool TryDecodeComponent(ReadOnlySpan<byte> component, out string value)
    {
        value = string.Empty;
        var decoded = new byte[component.Length];
        var written = 0;
        for (var index = 0; index < component.Length; index++)
        {
            var current = component[index];
            if (current == '+')
            {
                decoded[written++] = (byte)' ';
                continue;
            }

            if (current != '%')
            {
                decoded[written++] = current;
                continue;
            }

            if (index + 2 >= component.Length
                || !TryReadHexNibble(component[index + 1], out var high)
                || !TryReadHexNibble(component[index + 2], out var low))
            {
                return false;
            }

            decoded[written++] = (byte)((high << 4) | low);
            index += 2;
        }

        try
        {
            value = StrictUtf8.GetString(decoded.AsSpan(0, written));
            return true;
        }
        catch (Exception exception) when (exception is DecoderFallbackException or ArgumentException)
        {
            return false;
        }
    }

    private static bool TryReadHexNibble(byte character, out int nibble)
    {
        nibble = character switch
        {
            >= (byte)'0' and <= (byte)'9' => character - (byte)'0',
            >= (byte)'a' and <= (byte)'f' => character - (byte)'a' + 10,
            >= (byte)'A' and <= (byte)'F' => character - (byte)'A' + 10,
            _ => -1
        };
        return nibble >= 0;
    }

    private static bool IsAdmittedFormContentType(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType)
            || !MediaTypeHeaderValue.TryParse(contentType, out var parsed)
            || !parsed.MediaType.Equals(FormUrlEncodedContentType, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Fail closed beyond the canonical text: a charset parameter must be utf-8, and any other
        // parameter makes the submission structurally inadmissible.
        foreach (var parameter in parsed.Parameters)
        {
            if (parameter.Name.Equals(CharsetParameterName, StringComparison.OrdinalIgnoreCase))
            {
                if (!parameter.Value.Equals(Utf8Charset, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        return true;
    }
}
