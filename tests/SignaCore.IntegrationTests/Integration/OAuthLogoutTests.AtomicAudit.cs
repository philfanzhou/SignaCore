using System.Data.Common;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Integration;

public sealed partial class OAuthLogoutTests
{
    [Theory]
    [InlineData("stage")]
    [InlineData("sql")]
    public async Task Prepare_AtomicAuditFailureIsFixed400AndNeverLeaksDependencyCanaries(string boundary)
    {
        await SeedLogoutAppAsync();
        var capture = new CapturingLoggerProvider();
        var fault = new LogoutCanarySqlFault();
        using var factory = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging => logging.AddProvider(capture)));
            services.AddDbContext<IdentityDbContext>(options => options.AddInterceptors(fault), optionsLifetime: ServiceLifetime.Singleton);
            if (boundary == "stage")
            {
                services.AddScoped<IAuditService>(provider =>
                {
                    var context = provider.GetRequiredService<IdentityDbContext>();
                    var repository = new AuditLogRepository(context);
                    var mock = new Mock<IAuditLogRepository>();
                    mock.Setup(repo => repo.AddAsync(It.IsAny<AuditLogEntity>(), It.IsAny<CancellationToken>()))
                        .Returns(async (AuditLogEntity row, CancellationToken token) =>
                        {
                            await repository.AddAsync(row, token);
                            if (row.Action == "oidc.logout.prepared") throw new InvalidOperationException(fault.Text, new Exception(fault.Text));
                        });
                    return new AuditService(new LoginHistoryRepository(context), mock.Object);
                });
            }
        });
        var (account, session, cookie) = await LoginAndCaptureSessionAsync(factory);
        var hint = await MintIdTokenAsync(account, session);
        var canaries = new[] { hint, cookie, State, RegisteredPostLogoutUri, AppSecret, "raw-handle-dependency-canary-345" };
        fault.Text = string.Join("|", canaries);
        fault.Enabled = boundary == "sql";
        var beforeRows = await QueryAsync(context => context.LogoutRequests.CountAsync(TestContext.Current.CancellationToken));
        var beforeAudit = await QueryAsync(context => context.AuditLogs.CountAsync(TestContext.Current.CancellationToken));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader();
        using var response = await client.PostAsync("/oauth2/logout/requests", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["id_token_hint"] = hint, ["post_logout_redirect_uri"] = RegisteredPostLogoutUri, ["state"] = State
        }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var dump = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)
            + response.Headers + response.Content.Headers + string.Join("\n", capture.Messages);
        Assert.Contains("invalid_request", dump, StringComparison.Ordinal);
        Assert.All(canaries, canary => Assert.False(dump.Contains(canary, StringComparison.Ordinal)));
        Assert.DoesNotContain(capture.Messages, message => message.Contains("Logout request prepared", StringComparison.Ordinal));
        Assert.Equal(beforeRows, await QueryAsync(context => context.LogoutRequests.CountAsync(TestContext.Current.CancellationToken)));
        Assert.Equal(beforeAudit, await QueryAsync(context => context.AuditLogs.CountAsync(TestContext.Current.CancellationToken)));
        if (boundary == "sql") Assert.True(fault.Observed);
    }

    private sealed class LogoutCanarySqlFault : DbCommandInterceptor
    {
        public bool Enabled, Observed;
        public string Text = "";
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (Enabled && command.CommandText.Contains("INSERT INTO \"logout_requests\"", StringComparison.Ordinal))
            {
                Observed = true;
                throw new InvalidOperationException(Text, new Exception(Text));
            }
            return ValueTask.FromResult(result);
        }
    }
}
