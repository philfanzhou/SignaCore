namespace SignaCore.Domain.Models;

/// <summary>
/// 分页响应。<paramref name="Total"/> 是**满足条件的总条数**，不是当前页条数——
/// 前端靠它算总页数。
/// </summary>
public sealed record PagedResponse<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

/// <summary>
/// 分页入参归一化。所有列表接口共用同一套边界规则，避免各自抄一份后逐渐漂移。
/// </summary>
public readonly record struct PageRequest(int Page, int PageSize)
{
    public const int DefaultPageSize = 20;
    public const int MaxPageSize = 100;

    /// <summary>页码从 1 开始；页大小落在 [1, <see cref="MaxPageSize"/>]，缺省为 <see cref="DefaultPageSize"/>。</summary>
    public static PageRequest Normalize(int? page, int? pageSize)
    {
        var normalizedPage = Math.Max(page.GetValueOrDefault(1), 1);
        var requestedPageSize = pageSize.GetValueOrDefault(DefaultPageSize);
        if (requestedPageSize < 1)
        {
            requestedPageSize = DefaultPageSize;
        }

        return new PageRequest(normalizedPage, Math.Min(requestedPageSize, MaxPageSize));
    }

    public int Skip => (Page - 1) * PageSize;
}
