using System.Text;
using Microsoft.AspNetCore.Http;

namespace SignaCore.Host.Management;

/// <summary>
/// A product-side fixed management JSON answer: a pre-rendered closed body with its fixed status,
/// in the same style as the shared library's fixed results. The body is constant per call site and
/// carries no request data, values, or exception details.
/// </summary>
internal sealed class FixedJsonResult(byte[] body, int statusCode) : IResult
{
    public async Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        if (!httpContext.Response.HasStarted)
        {
            httpContext.Response.StatusCode = statusCode;
            httpContext.Response.ContentType = "application/json";
            httpContext.Response.ContentLength = body.Length;
            await httpContext.Response.Body.WriteAsync(body, httpContext.RequestAborted);
        }
    }

    internal static FixedJsonResult Create(string body, int statusCode) =>
        new(Encoding.UTF8.GetBytes(body), statusCode);
}
