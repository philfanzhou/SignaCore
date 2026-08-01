using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Domain.Keys;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain.Keys;

/// <summary>
/// 主密钥来源的优先级与派生方式。派生参数改变会导致存量 RSA 私钥无法解密，
/// 因此这里把"环境变量口令 → 主密钥"的映射也钉死。
/// </summary>
[Collection(MasterKeyStateCollection.Name)]
public class FileMasterKeyProviderTests : IDisposable
{
    private readonly string? _previousMasterKey;
    private readonly string _masterKeyFilePath;

    public FileMasterKeyProviderTests()
    {
        _previousMasterKey = Environment.GetEnvironmentVariable("RSA_MASTER_KEY");
        _masterKeyFilePath = Path.Combine(
            AppContext.BaseDirectory, "data", "master-key", "master-key.json");
    }

    private static FileMasterKeyProvider CreateProvider() =>
        new(NullLogger<FileMasterKeyProvider>.Instance);

    [Fact]
    public void GetMasterKey_WithEnvironmentVariable_DerivesViaHkdfWithPinnedParameters()
    {
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", "some-operator-supplied-passphrase");

        var actual = CreateProvider().GetMasterKey();

        // 独立重算一遍：口令经 HKDF-SHA256(salt=MasterKeyHkdfSalt, info=MasterKeyHkdfInfo) 派生 32 字节。
        var expected = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            Encoding.UTF8.GetBytes("some-operator-supplied-passphrase"),
            32,
            Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfSalt),
            Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfInfo));

        Assert.Equal(expected, actual);
        Assert.Equal(32, actual.Length);
    }

    [Fact]
    public void GetMasterKey_IsStableAcrossCalls()
    {
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", "stable-passphrase");
        var provider = CreateProvider();

        Assert.Equal(provider.GetMasterKey(), provider.GetMasterKey());
    }

    [Fact]
    public void GetMasterKey_EnvironmentVariableWins_OverExistingFile()
    {
        // 先让一次无环境变量的取值把文件落盘
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", null);
        var fromFile = CreateProvider().GetMasterKey();
        Assert.True(File.Exists(_masterKeyFilePath));

        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", "env-wins");
        var fromEnv = CreateProvider().GetMasterKey();

        Assert.NotEqual(fromFile, fromEnv);
    }

    [Fact]
    public void GetMasterKey_WithoutEnvironmentVariable_PersistsAndReusesFile()
    {
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", null);
        if (File.Exists(_masterKeyFilePath))
        {
            File.Delete(_masterKeyFilePath);
        }

        var first = CreateProvider().GetMasterKey();

        Assert.True(File.Exists(_masterKeyFilePath));
        var persisted = JsonSerializer.Deserialize<MasterKeyFile>(File.ReadAllText(_masterKeyFilePath));
        Assert.NotNull(persisted);
        Assert.Equal(first, Convert.FromBase64String(persisted!.EncodedKey));

        // 新建的 provider 必须复用同一份文件，而不是再生成一把
        Assert.Equal(first, CreateProvider().GetMasterKey());
    }

    [Fact]
    public void GetMasterKey_WithCorruptFile_RegeneratesInsteadOfThrowing()
    {
        // 坏文件不能让服务永远起不来：当作"没有"，重新生成。
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", null);
        Directory.CreateDirectory(Path.GetDirectoryName(_masterKeyFilePath)!);
        File.WriteAllText(_masterKeyFilePath, "{ this is not valid json");

        var key = CreateProvider().GetMasterKey();

        Assert.Equal(32, key.Length);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", _previousMasterKey);
    }
}
