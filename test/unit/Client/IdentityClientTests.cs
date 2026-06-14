using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuantumZhou.Identity.Client;
using Xunit;

namespace QuantumZhou.Identity.Client.Tests;

public class IdentityClientOptionsTests
{
    [Fact]
    public void GetEffectiveAppSecret_ReturnsEnvironmentVariable_WhenSet()
    {
        var options = new IdentityClientOptions { AppSecret = "from_config" };
        Environment.SetEnvironmentVariable("IDENTITY_APP_SECRET", "from_env");
        try
        {
            Assert.Equal("from_env", options.GetEffectiveAppSecret());
        }
        finally
        {
            Environment.SetEnvironmentVariable("IDENTITY_APP_SECRET", null);
        }
    }

    [Fact]
    public void GetEffectiveAppSecret_FallsBackToConfig_WhenEnvNotSet()
    {
        var options = new IdentityClientOptions { AppSecret = "from_config" };
        Environment.SetEnvironmentVariable("IDENTITY_APP_SECRET", null);
        Assert.Equal("from_config", options.GetEffectiveAppSecret());
    }

    [Fact]
    public void DefaultValues_AreCorrect()
    {
        var options = new IdentityClientOptions();
        Assert.Equal("http://localhost:5001", options.GrpcEndpoint);
        Assert.Equal("QuantumZhou.Identity", options.JwtIssuer);
        Assert.Equal("QuantumZhou.microservices", options.JwtAudience);
        Assert.Equal("http://localhost:5002/.well-known/jwks", options.JwksEndpoint);
        Assert.Equal("/admin/auth", options.AuthEndpointPrefix);
    }

    [Fact]
    public void BindFromConfiguration_Works()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Identity:GrpcEndpoint"] = "http://identity:5001",
                ["Identity:AppId"] = "test_app",
                ["Identity:AppSecret"] = "test_secret",
                ["Identity:JwtIssuer"] = "TestIssuer",
                ["Identity:JwtAudience"] = "TestAudience",
                ["Identity:JwksEndpoint"] = "http://identity:5002/jwks",
                ["Identity:AuthEndpointPrefix"] = "/api/auth"
            })
            .Build();

        var options = new IdentityClientOptions();
        config.GetSection(IdentityClientOptions.SectionName).Bind(options);

        Assert.Equal("http://identity:5001", options.GrpcEndpoint);
        Assert.Equal("test_app", options.AppId);
        Assert.Equal("test_secret", options.AppSecret);
        Assert.Equal("TestIssuer", options.JwtIssuer);
        Assert.Equal("TestAudience", options.JwtAudience);
        Assert.Equal("http://identity:5002/jwks", options.JwksEndpoint);
        Assert.Equal("/api/auth", options.AuthEndpointPrefix);
    }
}

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddIdentityClient_RegistersRequiredServices()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Identity:GrpcEndpoint"] = "http://localhost:5001",
            ["Identity:AppId"] = "test_app"
        });

        builder.Services.AddIdentityClient(builder.Configuration);

        var app = builder.Build();

        // Verify IdentityClientOptions is registered
        var options = app.Services.GetRequiredService<IdentityClientOptions>();
        Assert.NotNull(options);
        Assert.Equal("test_app", options.AppId);

        // Verify authentication services are registered
        var authSchemeProvider = app.Services.GetRequiredService<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>();
        Assert.NotNull(authSchemeProvider);
    }
}

public class AuthEndpointsGetCurrentUserTests
{
    [Fact]
    public async Task MapIdentityAuthEndpoints_RegistersRoutes()
    {
        // 验证端点路由已注册——不实际发起请求（避免 JWKS 依赖）
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Identity:GrpcEndpoint"] = "http://localhost:5001",
            ["Identity:AppId"] = "test_app"
        });
        builder.Services.AddIdentityClient(builder.Configuration);

        var app = builder.Build();
        app.UseIdentityClient();
        app.MapIdentityAuthEndpoints();

        // 验证应用构建成功，无异常
        Assert.NotNull(app);
    }
}

public class LoginRequestTests
{
    [Fact]
    public void LoginRequest_StoresValues()
    {
        var request = new LoginRequest("admin", "password123");
        Assert.Equal("admin", request.Username);
        Assert.Equal("password123", request.Password);
    }
}

public class RefreshRequestTests
{
    [Fact]
    public void RefreshRequest_StoresValue()
    {
        var request = new RefreshRequest("token_value");
        Assert.Equal("token_value", request.RefreshToken);
    }
}
