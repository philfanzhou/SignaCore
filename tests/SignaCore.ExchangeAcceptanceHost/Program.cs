extern alias provider;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services.Sms;
using Fixture = provider::SignaCore.Tests.Integration.IdentityServerFixture;

// Owned loopback fixture for cross-repository acceptance; never registers in a production solution.
if (args.Length != 2) throw new ArgumentException("Expected output JSON path and SignaCore repository root.");
Environment.SetEnvironmentVariable("ASPNETCORE_TEST_CONTENTROOT_SIGNACORE_HOST", Path.Combine(args[1], "src/SignaCore.Host"));
await using var fixture = new Fixture();
await fixture.InitializeAsync();
var sender = new AcceptanceSms();
using var providerHost = fixture.WithTestServices(services =>
{
    services.Replace(ServiceDescriptor.Singleton(new SmsOptions
    {
        OtpHmacKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        Profiles = new(StringComparer.OrdinalIgnoreCase) { ["acceptance"] = new() { Provider = sender.Provider } }
    }));
    services.AddSingleton<ISmsSender>(sender);
    // Exercise the real callback client against this owned numeric-loopback fixture.
    services.Replace(ServiceDescriptor.Singleton(new SignaCore.Domain.CallbackUrlValidator(new[] { "127.0.0.1" }, true, false)));
    services.AddHttpClient("Callback").ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
});
using var providerHttp = providerHost.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
var accountId = await fixture.GetAdminAccountIdAsync();
var builder = WebApplication.CreateBuilder();
builder.WebHost.UseUrls("http://127.0.0.1:0");
var app = builder.Build();
var roles = new[] { "alpha", "beta", "gamma" };
app.MapGet("/__otp", (string phone) => sender.Codes.TryGetValue(phone, out var code) ? Results.Json(new { code }) : Results.NotFound());
app.MapPost("/__control", async (JsonElement body) =>
{
    using var scope = fixture.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
    if (body.TryGetProperty("application", out var application))
    {
        var callback = new Uri(body.GetProperty("callbackUrl").GetString()!);
        if (callback.Host != "127.0.0.1" || callback.Scheme != "http") return Results.BadRequest();
        (await db.AppRegistrations.SingleAsync(a => a.AppId == "acceptance-" + application.GetString())).CallbackUrl = callback.ToString();
    }
    if (body.TryGetProperty("accountActive", out var active))
        (await db.Accounts.SingleAsync(a => a.Id == accountId)).IsActive = active.GetBoolean();
    if (body.TryGetProperty("removeTrustFrom", out var from))
    {
        var to = body.GetProperty("removeTrustTo").GetString();
        var source = await db.AppRegistrations.SingleAsync(a => a.AppId == "acceptance-" + from.GetString());
        var target = await db.AppRegistrations.SingleAsync(a => a.AppId == "acceptance-" + to);
        db.AppExchangeTrusts.RemoveRange(db.AppExchangeTrusts.Where(t => t.SourceAppRegistrationId == source.Id && t.AppRegistrationId == target.Id));
    }
    await db.SaveChangesAsync();
    return Results.Ok();
});
app.MapFallback(async context =>
{
    using var request = new HttpRequestMessage(new HttpMethod(context.Request.Method), context.Request.Path + context.Request.QueryString);
    if (context.Request.ContentLength > 0 || context.Request.Headers.ContainsKey("Transfer-Encoding")) request.Content = new StreamContent(context.Request.Body);
    foreach (var header in context.Request.Headers)
        if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray())) request.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
    using var response = await providerHttp.SendAsync(request);
    context.Response.StatusCode = (int)response.StatusCode;
    context.Response.ContentType = response.Content.Headers.ContentType?.ToString();
    await response.Content.CopyToAsync(context.Response.Body);
});
await app.StartAsync();
var address = app.Urls.Single();
using (var scope = fixture.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
    foreach (var role in roles)
    {
        await fixture.SeedGatewayAppAsync("acceptance-" + role, "synthetic-" + role + "-secret");
        var registration = await db.AppRegistrations.SingleAsync(a => a.AppId == "acceptance-" + role);
        registration.SmsLoginMode = SmsLoginMode.AutoProvision;
        registration.SmsProfileKey = "acceptance";
    }
    foreach (var from in roles) foreach (var to in roles.Where(x => x != from))
        db.AppExchangeTrusts.Add(new AppExchangeTrustEntity
        {
            Id = Guid.NewGuid(), SourceAppRegistrationId = (await db.AppRegistrations.SingleAsync(a => a.AppId == "acceptance-" + from)).Id,
            AppRegistrationId = (await db.AppRegistrations.SingleAsync(a => a.AppId == "acceptance-" + to)).Id, CreatedAt = DateTimeOffset.UtcNow
        });
    // Synthetic phones link to the known fixture account; real OTP validation still runs.
    foreach (var phone in new[] { "+8613900000001", "+8613900000002", "+8613900000003" })
        db.UserLogins.Add(new UserLoginEntity { Id = Guid.NewGuid(), AccountId = accountId, ProviderName = IdentityConstants.AuthMethodSms, ProviderUserId = phone });
    await db.SaveChangesAsync();
}
var discovery = await providerHttp.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration");
await File.WriteAllTextAsync(args[0], JsonSerializer.Serialize(new { address, accountId, issuer = discovery.GetProperty("issuer").GetString(), audience = fixture.SharedAudience }));
await app.WaitForShutdownAsync();

sealed class AcceptanceSms : ISmsSender
{
    public string Provider => "ExchangeAcceptance";
    public ConcurrentDictionary<string, string> Codes { get; } = new();
    public Task<SmsSendResult> SendAsync(SmsProviderProfile profile, SmsVerificationMessage message, CancellationToken cancellationToken)
    {
        Codes[message.PhoneE164] = message.Code;
        return Task.FromResult(new SmsSendResult(Provider, Guid.NewGuid().ToString("N")));
    }
}
