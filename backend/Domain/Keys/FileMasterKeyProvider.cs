using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Database;

namespace QuantumZhou.Identity.Domain.Keys;

/// <summary>data/master-key/master-key.json 的文件结构。</summary>
public sealed class MasterKeyFile
{
    public string EncodedKey { get; set; } = string.Empty;
    public DateTimeOffset GeneratedAt { get; set; }
}

/// <summary>
/// 主密钥来源，按优先级：环境变量 <c>RSA_MASTER_KEY</c>（经 HKDF 派生）→
/// <c>data/master-key/master-key.json</c> → 现场生成并落盘。
/// <para>
/// 生产环境必须显式设置 <c>RSA_MASTER_KEY</c>：落盘的那份随容器文件系统走，
/// 丢了就意味着存量 RSA 私钥无法解密、已签发的 JWT 全部失效。
/// </para>
/// <para>
/// 取值是惰性的且只做一次：构造本类不产生任何磁盘副作用，首次
/// <see cref="GetMasterKey"/> 才会读取（并可能创建目录与密钥文件）。
/// </para>
/// </summary>
public sealed class FileMasterKeyProvider : IMasterKeyProvider
{
    private const string MasterKeyEnvironmentVariable = "RSA_MASTER_KEY";
    private const int MasterKeySizeBytes = 32;

    private readonly ILogger<FileMasterKeyProvider> _logger;
    private readonly string _masterKeyDirectory;
    private readonly string _masterKeyFilePath;
    private readonly Lazy<byte[]> _masterKey;

    public FileMasterKeyProvider(ILogger<FileMasterKeyProvider> logger)
    {
        _logger = logger;
        _masterKeyDirectory = Path.Combine(AppContext.BaseDirectory, "data", "master-key");
        _masterKeyFilePath = Path.Combine(_masterKeyDirectory, "master-key.json");
        _masterKey = new Lazy<byte[]>(Resolve, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public byte[] GetMasterKey() => _masterKey.Value;

    private byte[] Resolve()
    {
        var envMasterKey = Environment.GetEnvironmentVariable(MasterKeyEnvironmentVariable);
        if (!string.IsNullOrEmpty(envMasterKey))
        {
            // 环境变量是任意长度的口令，先经 HKDF 派生成定长密钥。
            // salt/info 的字面值参与派生，改动会导致存量私钥无法解密。
            var derivedKey = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                Encoding.UTF8.GetBytes(envMasterKey),
                MasterKeySizeBytes,
                Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfSalt),
                Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfInfo));
            _logger.LogInformation("Using RSA master key from environment variable");
            return derivedKey;
        }

        if (!Directory.Exists(_masterKeyDirectory))
        {
            Directory.CreateDirectory(_masterKeyDirectory);
        }

        var existingKey = ReadFile();
        if (existingKey != null)
        {
            _logger.LogInformation("Loaded existing RSA master key from file");
            return existingKey;
        }

        _logger.LogInformation("No RSA master key file found, generating new one");
        return GenerateAndSave();
    }

    private byte[]? ReadFile()
    {
        if (!File.Exists(_masterKeyFilePath))
        {
            return null;
        }

        try
        {
            var json = File.ReadAllText(_masterKeyFilePath);
            var file = JsonSerializer.Deserialize<MasterKeyFile>(json);
            if (file == null || string.IsNullOrEmpty(file.EncodedKey))
            {
                return null;
            }

            return Convert.FromBase64String(file.EncodedKey);
        }
        catch
        {
            // 文件损坏/格式不对：当作"没有"，走生成新密钥的分支。
            // 这里不能 fail-fast，否则一个坏文件会让服务永远起不来。
            return null;
        }
    }

    private byte[] GenerateAndSave()
    {
        var keyBytes = RandomNumberGenerator.GetBytes(MasterKeySizeBytes);

        var file = new MasterKeyFile
        {
            EncodedKey = Convert.ToBase64String(keyBytes),
            GeneratedAt = DateTimeOffset.UtcNow
        };

        var json = JsonSerializer.Serialize(file, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_masterKeyFilePath, json);

        _logger.LogInformation("New RSA master key generated and saved to {Path}", _masterKeyFilePath);
        return keyBytes;
    }
}
