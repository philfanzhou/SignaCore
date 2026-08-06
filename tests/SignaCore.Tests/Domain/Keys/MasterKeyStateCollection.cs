using Xunit;

namespace SignaCore.Tests.Domain.Keys;

/// <summary>
/// 把所有会改动进程级主密钥状态的测试类归到同一个 collection，避免并行互相踩。
/// <para>
/// 涉及的共享状态有两处，都是进程/文件系统全局的：
/// <list type="bullet">
/// <item>环境变量 <c>RSA_MASTER_KEY</c></item>
/// <item>文件 <c>{BaseDirectory}/data/master-key/master-key.json</c></item>
/// </list>
/// xUnit 默认并行执行不同测试类；同属一个 collection 的类则串行。
/// 没有这个约束时实测约每 5 次全量跑会偶发失败一次。
/// </para>
/// </summary>
[CollectionDefinition(Name)]
public sealed class MasterKeyStateCollection
{
    public const string Name = "MasterKeyState";
}
