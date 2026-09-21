extern alias BffSample;
using BffSample::SignaCore.ReferenceBff;
using ServiceMantle.Installation;
using Microsoft.Extensions.Configuration;
using SignaCore.ReferenceBff.Database;
using Xunit;

namespace SignaCore.ReferenceBff.Tests;

public sealed class ReferenceBffSetupCodeTests
{
    [Theory]
    [InlineData("--setup-code")]
    [InlineData("--setup-code", "unknown")]
    [InlineData("--setup-code", "CREATE")]
    [InlineData("--setup-code", "create", "--setup-code", "rotate")]
    [InlineData("--setup-code=create")]
    [InlineData("--setup-code", "create", "extra")]
    public async Task InvalidArguments_NeverOpenDatabase(params string[] args)
    {
        Assert.True(SetupCodeCommand.IsRequested(args));
        Assert.Equal(2, await SetupCodeCommand.RunAsync(args, new SilentTerminal(),
            () => throw new Xunit.Sdk.XunitException("Database must not open."), CancellationToken.None));
    }

    [Fact]
    public async Task NoninteractiveTerminal_NeverOpensDatabase()
    {
        Assert.Equal(2, await SetupCodeCommand.RunAsync(["--setup-code", "create"],
            new SilentTerminal { IsInteractive = false },
            () => throw new Xunit.Sdk.XunitException("Database must not open."), CancellationToken.None));
        Assert.False(SetupCodeCommand.IsRequested([]));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("SQLite", null)]
    [InlineData(null, "synthetic")]
    [InlineData("unknown", "synthetic")]
    public async Task IncompleteConfiguration_IsFixedDependencyFailure(string? provider, string? connection)
    {
        using var configuration = new ConfigurationManager();
        configuration["ReferenceBffDatabase:Provider"] = provider;
        configuration["ReferenceBffDatabase:ConnectionString"] = connection;
        var terminal = new SilentTerminal();
        Assert.Equal(4, await SetupCodeCommand.RunAsync(["--setup-code", "create"], terminal,
            () => SetupCodeCommand.CreateSession(configuration), TestContext.Current.CancellationToken));
        Assert.Equal(0, terminal.Displays);
    }

    public static IEnumerable<object[]> Boundaries =>
        from boundary in new[] { "Begin", "Binding", "Find", "Initialize", "Issue", "Commit", "Dispose", "Display" }
        from failure in new[] { "none", "ordinary", "internal-cancel" }
        from cancel in new[] { false, true }
        select new object[] { boundary, failure, cancel };

    [Theory]
    [MemberData(nameof(Boundaries))]
    public async Task EveryBoundary_ObservesCallerAfterCompletionOrFailure(
        string boundary, string failure, bool cancel)
    {
        using var caller = new CancellationTokenSource();
        var session = new FakeSession(caller.Token);
        var terminal = new SilentTerminal();
        void Hook(string current)
        {
            if (current != boundary) return;
            if (cancel) caller.Cancel();
            if (failure == "ordinary") throw new IOException("Synthetic failure.");
            if (failure == "internal-cancel") throw new OperationCanceledException();
        }
        session.After = Hook;
        terminal.After = () => Hook("Display");
        var exit = await SetupCodeCommand.RunAsync(["--setup-code", "create"], terminal,
            () => session, caller.Token);
        Assert.Equal(cancel ? 130 : failure == "none" ? 0 : 4, exit);
        Assert.True(session.Disposed);
        Assert.Equal(exit == 0 || boundary == "Display" ? 1 : 0, terminal.Displays);
        if (cancel || failure != "none")
        {
            Assert.Equal(boundary is "Commit" or "Dispose" or "Display", session.Committed);
        }
    }

    [Fact]
    public async Task PreCanceledCaller_TakesPriorityWithoutTerminalOrDatabase()
    {
        Assert.Equal(130, await SetupCodeCommand.RunAsync([], new SilentTerminal(),
            () => throw new Xunit.Sdk.XunitException("Database must not open."),
            new CancellationToken(true)));
    }

    internal sealed class SilentTerminal : ISetupCodeTerminal
    {
        public bool IsInteractive { get; init; } = true;
        public int Displays { get; private set; }
        public SetupCode? Code { get; private set; }
        public Action? After { get; set; }
        public void Display(SetupCode code)
        {
            Displays++;
            Code = code;
            After?.Invoke();
        }
    }

    private sealed class FakeSession(CancellationToken original) : ISetupCodeSession
    {
        public Action<string>? After { get; set; }
        public bool Disposed { get; private set; }
        public bool Committed { get; private set; }
        private void End(string name, CancellationToken token)
        {
            Assert.Equal(original, token);
            After?.Invoke(name);
        }
        public ValueTask BeginAsync(CancellationToken token) { End("Begin", token); return ValueTask.CompletedTask; }
        public ValueTask<bool> HasBindingAsync(CancellationToken token) { End("Binding", token); return ValueTask.FromResult(false); }
        public ValueTask<ServiceInstallationState?> FindAsync(CancellationToken token) { End("Find", token); return ValueTask.FromResult<ServiceInstallationState?>(null); }
        public ValueTask InitializeAsync(CancellationToken token) { End("Initialize", token); return ValueTask.CompletedTask; }
        public ValueTask<SetupCodeIssueResult> IssueAsync(bool rotate, CancellationToken token)
        {
            End("Issue", token);
            return ValueTask.FromResult(SetupCodeIssueResult.Issued(SetupCode.Generate(), 1, DateTime.UtcNow.AddMinutes(30)));
        }
        public ValueTask CommitAsync(CancellationToken token) { Committed = true; End("Commit", token); return ValueTask.CompletedTask; }
        public ValueTask DisposeAsync() { Disposed = true; After?.Invoke("Dispose"); return ValueTask.CompletedTask; }
    }
}
