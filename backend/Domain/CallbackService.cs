using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Database;

namespace QuantumZhou.Identity.Domain;

public interface ICallbackService
{
    Task<List<Claim>> FetchExternalClaimsAsync(string callbackUrl, string userId);
}

public class CallbackService : ICallbackService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<CallbackService> _logger;
    private readonly CallbackUrlValidator _urlValidator;
    private const int TimeoutSeconds = IdentityConstants.CallbackTimeoutSeconds;

    public CallbackService(IHttpClientFactory httpClientFactory, ILogger<CallbackService> logger, CallbackUrlValidator urlValidator)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _urlValidator = urlValidator;
    }

    public async Task<List<Claim>> FetchExternalClaimsAsync(string callbackUrl, string userId)
    {
        var urlValidation = _urlValidator.Validate(callbackUrl);
        if (!urlValidation.IsValid)
        {
            _logger.LogWarning("Callback URL validation failed: {Url}, Reason={Reason}", callbackUrl, urlValidation.ErrorMessage);
            return new List<Claim>();
        }

        try
        {
            using var client = _httpClientFactory.CreateClient("Callback");
            client.Timeout = TimeSpan.FromSeconds(TimeoutSeconds);

            var requestBody = new { user_id = userId };
            var response = await client.PostAsJsonAsync(callbackUrl, requestBody);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Callback request failed: {Url}, StatusCode: {StatusCode}", callbackUrl, response.StatusCode);
                return new List<Claim>();
            }

            var result = await response.Content.ReadFromJsonAsync<CallbackResponse>();
            if (result == null)
            {
                return new List<Claim>();
            }

            var claims = new List<Claim>();

            if (result.Roles != null)
            {
                foreach (var role in result.Roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }

            if (result.Permissions != null)
            {
                foreach (var permission in result.Permissions)
                {
                    claims.Add(new Claim(IdentityConstants.ClaimPermission, permission));
                }
            }

            if (result.CustomClaims != null)
            {
                foreach (var kvp in result.CustomClaims)
                {
                    claims.Add(new Claim(kvp.Key, kvp.Value));
                }
            }

            _logger.LogInformation("Successfully retrieved {Count} extended claims from {Url}", claims.Count, callbackUrl);
            return claims;
        }
        catch (TaskCanceledException)
        {
            _logger.LogWarning("Callback request timed out: {Url}", callbackUrl);
            return new List<Claim>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Callback request exception: {Url}", callbackUrl);
            return new List<Claim>();
        }
    }
}

public record CallbackResponse
{
    public List<string>? Roles { get; set; }
    public List<string>? Permissions { get; set; }
    public Dictionary<string, string>? CustomClaims { get; set; }
}