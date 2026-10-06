using System.Buffers;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using ServiceMantle.Configuration;

namespace SignaCore.Host.Management;

/// <summary>
/// The group-level endpoint filter that adds the product's <c>validationErrors</c> compatibility
/// field to the shared management setting update's validation rejection.
/// </summary>
/// <remarks>
/// The shared update endpoint answers a definite <c>ValidationFailed</c> with the fixed generic
/// 400 (<c>errorCode = management.request.invalid</c>). When — and only when — the consumer-owned
/// executor staged the closed validation metadata in <see cref="HttpContext.Items"/> for exactly
/// that outcome, this filter replaces the generic body with the same top-level error code plus
/// <c>validationErrors: [{key, errorCode}]</c>. The staged entries are the shared
/// <see cref="ServiceSettingValidationError"/> list: registered keys (a null key stays an explicit
/// JSON null) and product-fixed codes, never values, exceptions, candidates, or snapshots. The
/// filter matches the exact shared update path and POST method and passes every other endpoint of
/// the group through untouched; parse rejections happen before the executor runs and stage
/// nothing, so they keep the generic body, and 409/503/200 answers are never rewritten. It reads
/// the metadata only after <c>next</c> returned normally: a thrown exception — cancellation
/// included — propagates unchanged with nothing written.
/// </remarks>
internal sealed class ManagementSettingValidationErrorsFilter : IEndpointFilter
{
    /// <summary>The request-scoped staging slot for the executor's safe validation metadata.</summary>
    internal const string ItemsKey = "SignaCore.Management.SettingValidationErrors";

    // The exact update route of the shared management API v1 group at its fixed root.
    private const string UpdatePath = "/management/v1/settings";

    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var result = await next(context);
        var http = context.HttpContext;
        if (HttpMethods.IsPost(http.Request.Method)
            && http.Request.Path.Equals(UpdatePath, StringComparison.Ordinal)
            && http.Items.TryGetValue(ItemsKey, out var staged)
            && staged is IReadOnlyList<ServiceSettingValidationError> errors)
        {
            http.Items.Remove(ItemsKey);
            return new FixedJsonResult(
                RenderBody(errors), StatusCodes.Status400BadRequest);
        }

        return result;
    }

    private static byte[] RenderBody(IReadOnlyList<ServiceSettingValidationError> errors)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("errorCode", "management.request.invalid");
            writer.WriteStartArray("validationErrors");
            foreach (var error in errors)
            {
                writer.WriteStartObject();
                if (error.Key is null) writer.WriteNull("key");
                else writer.WriteString("key", error.Key);
                writer.WriteString("errorCode", error.ErrorCode);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }
}
