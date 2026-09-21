using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.ReferenceBff.Database;

namespace SignaCore.ReferenceBff;

// These boundaries keep secret delivery separate from persistence and allow cancellation and
// cleanup failures to be exercised without ever printing a code in a test runner.
internal interface ISetupCodeTerminal
{
    bool IsInteractive { get; }
    void Display(SetupCode code);
}

internal sealed class SetupCodeTerminal : ISetupCodeTerminal
{
    public bool IsInteractive => !Console.IsInputRedirected && !Console.IsOutputRedirected;

    public void Display(SetupCode code)
    {
        if (!IsInteractive)
        {
            throw new InvalidOperationException("Interactive terminal required.");
        }

        Console.Out.WriteLine(code.Reveal());
        Console.Out.Flush();
    }
}

internal interface ISetupCodeSession : IAsyncDisposable
{
    ValueTask BeginAsync(CancellationToken token);
    ValueTask<bool> HasBindingAsync(CancellationToken token);
    ValueTask<ServiceInstallationState?> FindAsync(CancellationToken token);
    ValueTask InitializeAsync(CancellationToken token);
    ValueTask<SetupCodeIssueResult> IssueAsync(bool rotate, CancellationToken token);
    ValueTask CommitAsync(CancellationToken token);
}

internal sealed class SetupCodeSession(ReferenceBffDbContext context) : ISetupCodeSession
{
    private readonly IServiceInstallationStore installations =
        new EfCoreServiceInstallationStore<ReferenceBffDbContext>(context);
    private readonly IServiceSetupCodeStore codes =
        new EfCoreServiceSetupCodeStore<ReferenceBffDbContext>(context);
    private IDbContextTransaction? transaction;

    public async ValueTask BeginAsync(CancellationToken token) =>
        transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, token);

    public async ValueTask<bool> HasBindingAsync(CancellationToken token) =>
        await context.ManagementRoleBindings.AsNoTracking().AnyAsync(
            row => row.Role == ManagementRoleBindingEntity.SystemAdministratorRole, token);

    public ValueTask<ServiceInstallationState?> FindAsync(CancellationToken token) =>
        installations.FindAsync(ReferenceBffServiceMantle.ServiceId, token);

    public async ValueTask InitializeAsync(CancellationToken token) =>
        await installations.CreatePendingAsync(ReferenceBffServiceMantle.ServiceId, token);

    public ValueTask<SetupCodeIssueResult> IssueAsync(bool rotate, CancellationToken token) => rotate
        ? codes.RotateAsync(ReferenceBffServiceMantle.ServiceId, token)
        : codes.CreateAsync(ReferenceBffServiceMantle.ServiceId, token);

    public async ValueTask CommitAsync(CancellationToken token) => await transaction!.CommitAsync(token);

    public async ValueTask DisposeAsync()
    {
        // Disposal rolls back uncommitted work. Always discard the tracker, even if transaction
        // cleanup fails; never retry or compensate a possibly committed operation.
        try
        {
            if (transaction is not null)
            {
                await transaction.DisposeAsync();
            }
        }
        finally
        {
            await context.DisposeAsync();
        }
    }
}

internal static class SetupCodeCommand
{
    internal static bool IsRequested(string[] args) => args.Any(arg =>
        arg.StartsWith("--setup-code", StringComparison.OrdinalIgnoreCase));

    internal static async Task<int> RunAsync(
        string[] args,
        ISetupCodeTerminal terminal,
        Func<ISetupCodeSession> createSession,
        CancellationToken token)
    {
        var cleanupFailed = false;
        try
        {
            token.ThrowIfCancellationRequested();
            if (args.Length != 2 || args[0] != "--setup-code"
                || args[1] is not ("create" or "rotate") || !terminal.IsInteractive)
            {
                return token.IsCancellationRequested ? 130 : 2;
            }

            token.ThrowIfCancellationRequested();
            SetupCodeIssueResult? issued = null;
            var result = 3;
            var session = createSession();
            try
            {
                token.ThrowIfCancellationRequested();
                await session.BeginAsync(token);
                token.ThrowIfCancellationRequested();
                var bound = await session.HasBindingAsync(token);
                token.ThrowIfCancellationRequested();
                if (!bound)
                {
                    var state = await session.FindAsync(token);
                    token.ThrowIfCancellationRequested();
                    var rotate = args[1] == "rotate";
                    if (state?.IsCompleted != true && (state is not null || !rotate))
                    {
                        if (state is null)
                        {
                            await session.InitializeAsync(token);
                            token.ThrowIfCancellationRequested();
                        }

                        issued = await session.IssueAsync(rotate, token);
                        token.ThrowIfCancellationRequested();
                        if (issued.IsIssued)
                        {
                            await session.CommitAsync(token);
                            token.ThrowIfCancellationRequested();
                            result = 0;
                        }
                    }
                }
            }

            finally
            {
                try { await session.DisposeAsync(); }
                catch (Exception) { cleanupFailed = true; throw; }
            }

            // IsIssued proves only a save. This point additionally requires confirmed commit and
            // successful transaction/context cleanup, with the original caller still present.
            token.ThrowIfCancellationRequested();
            if (result == 0)
            {
                terminal.Display(issued!.SetupCode!);
                token.ThrowIfCancellationRequested();
            }

            return result;
        }
        catch (Exception exception)
        {
            if (token.IsCancellationRequested)
            {
                return 130;
            }

            return !cleanupFailed && (exception is DbUpdateConcurrencyException
                || exception is ServiceInstallationStoreException
                {
                    ErrorCode: "installation.entity_invalid" or "installation.state_invariant_violation"
                }) ? 3 : 4;
        }
    }

    internal static ISetupCodeSession CreateSession()
    {
        // No host, logging providers, command-line configuration, OIDC validation or migration.
        using var configuration = new ConfigurationManager();
        configuration
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true)
            .AddEnvironmentVariables();
        return CreateSession(configuration);
    }

    internal static ISetupCodeSession CreateSession(IConfiguration configuration)
    {
        var settings = ReferenceBffDatabaseSetup.Read(configuration);
        if (!settings.IsConfigured)
        {
            throw new InvalidOperationException("Database configuration required.");
        }

        var options = new DbContextOptionsBuilder<ReferenceBffDbContext>();
        ReferenceBffDatabaseSetup.ConfigureDbContext(options, settings);
        return new SetupCodeSession(new ReferenceBffDbContext(options.Options));
    }

    internal static string ErrorCategory(int exitCode) => exitCode switch
    {
        2 => "Setup code usage or terminal rejected.",
        3 => "Setup code state or concurrency rejected.",
        130 => "Setup code operation canceled.",
        _ => "Setup code operation failed."
    };
}
