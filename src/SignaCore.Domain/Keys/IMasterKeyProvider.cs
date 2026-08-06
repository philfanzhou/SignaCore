namespace SignaCore.Domain.Keys;

/// <summary>
/// 提供用于加密 RSA 私钥的主密钥（32 字节）。
/// </summary>
public interface IMasterKeyProvider
{
    /// <summary>
    /// 取主密钥。实现应缓存结果——本方法可能触发磁盘读写。
    /// </summary>
    byte[] GetMasterKey();
}
