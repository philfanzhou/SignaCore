using ServiceMantle.Bootstrap;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Host.Bootstrap;

/// <summary>
/// The startup credential decision: provisioned prints the anchor and plaintext exactly once,
/// and every closed rejection fails without a plaintext and without touching the record.
/// </summary>
public sealed class BootstrapCredentialProvisionerTests : IAsyncLifetime
{
    private string _directory = string.Empty;
    private string _bootstrapPath = string.Empty;
    private string _recordPath = string.Empty;
    private TextWriter _originalOutput = null!;
    private StringWriter _captured = null!;

    public ValueTask InitializeAsync()
    {
        _directory = Path.Combine(Path.GetTempPath(), $"signacore-provision-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
        _bootstrapPath = Path.Combine(_directory, "signacore.bootstrap.json");
        _recordPath = Path.Combine(_directory, "signacore.bootstrap-credential.json");
        _originalOutput = Console.Out;
        _captured = new StringWriter();
        Console.SetOut(_captured);
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        Console.SetOut(_originalOutput);
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task TwoConsecutiveStarts_PrintDifferentCredentialsAndInvalidateThePreviousOne()
    {
        var first = await BootstrapCredentialProvisioner.ProvisionAsync(_bootstrapPath);
        Assert.Equal(BootstrapCredentialStartupOutcome.Provisioned, first.Outcome);
        Assert.NotNull(first.Store);

        var lines = _captured.ToString().Split('\n', '\r');
        var anchorIndex = Array.IndexOf(lines, "one-time bootstrap credential:");
        Assert.True(anchorIndex >= 0);
        var firstPlaintext = lines[anchorIndex + 1];
        Assert.False(string.IsNullOrWhiteSpace(firstPlaintext));
        Assert.Single(lines, line => line == "one-time bootstrap credential:");

        _captured.GetStringBuilder().Clear();
        var second = await BootstrapCredentialProvisioner.ProvisionAsync(_bootstrapPath);
        Assert.Equal(BootstrapCredentialStartupOutcome.Provisioned, second.Outcome);

        var secondLines = _captured.ToString().Split('\n', '\r');
        var secondAnchor = Array.IndexOf(secondLines, "one-time bootstrap credential:");
        var secondPlaintext = secondLines[secondAnchor + 1];
        Assert.NotEqual(firstPlaintext, secondPlaintext);

        // The previous start's plaintext no longer verifies; the current one does.
        var verifier = second.Store!;
        Assert.Equal(
            BootstrapCredentialVerificationState.Invalid,
            (await verifier.VerifyAsync(firstPlaintext, TestContext.Current.CancellationToken)).State);
        Assert.Equal(
            BootstrapCredentialVerificationState.Valid,
            (await verifier.VerifyAsync(secondPlaintext, TestContext.Current.CancellationToken)).State);
    }

    [Fact]
    public async Task CorruptRecord_FailsWithoutAPlaintextAndLeavesTheRecordUnchanged()
    {
        await File.WriteAllTextAsync(_recordPath, "not a credential record", TestContext.Current.CancellationToken);
        var before = await File.ReadAllTextAsync(_recordPath, TestContext.Current.CancellationToken);

        var outcome = await BootstrapCredentialProvisioner.ProvisionAsync(
            BootstrapCredentialProvisioner.CreateStore(_bootstrapPath),
            _recordPath,
            _bootstrapPath);

        Assert.Equal(BootstrapCredentialStartupOutcome.Failed, outcome);
        var output = _captured.ToString();
        Assert.DoesNotContain("one-time bootstrap credential:", output, StringComparison.Ordinal);
        Assert.Contains(_recordPath, output, StringComparison.Ordinal);
        Assert.Equal(before, await File.ReadAllTextAsync(_recordPath, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AlreadyExistsRejection_FailsWithoutAPlaintext()
    {
        var outcome = await BootstrapCredentialProvisioner.ProvisionAsync(
            new FixedOutcomeReissuer(
                BootstrapCredentialProvisionResult.Rejected(
                    WellKnownBootstrapCredentialErrorCodes.AlreadyExists)),
            _recordPath,
            _bootstrapPath);

        Assert.Equal(BootstrapCredentialStartupOutcome.Failed, outcome);
        Assert.DoesNotContain("one-time bootstrap credential:", _captured.ToString(), StringComparison.Ordinal);
        Assert.Contains(_recordPath, _captured.ToString(), StringComparison.Ordinal);
        Assert.False(File.Exists(_recordPath));
    }

    [Fact]
    public async Task BootstrapConfiguredRejection_ContinuesAsAConfiguredInstance()
    {
        var outcome = await BootstrapCredentialProvisioner.ProvisionAsync(
            new FixedOutcomeReissuer(
                BootstrapCredentialProvisionResult.Rejected(
                    WellKnownBootstrapCredentialErrorCodes.BootstrapConfigured)),
            _recordPath,
            _bootstrapPath);

        Assert.Equal(BootstrapCredentialStartupOutcome.AlreadyConfigured, outcome);
        Assert.DoesNotContain("one-time bootstrap credential:", _captured.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void TheRecordSitsBesideTheBootstrapFile()
    {
        var store = BootstrapCredentialProvisioner.CreateStore(_bootstrapPath);
        Assert.Equal(_recordPath, store.FilePath);
        Assert.Equal(_bootstrapPath, store.BootstrapFilePath);
    }

    private sealed class FixedOutcomeReissuer(BootstrapCredentialProvisionResult result) : IBootstrapCredentialReissuer
    {
        public ValueTask<BootstrapCredentialProvisionResult> ReissueAsync(
            BootstrapCredentialLifetime lifetime,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(result);
    }
}
