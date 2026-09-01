namespace SignaCore.Domain.Models;

/// <summary>
/// A paged response. <paramref name="Total"/> is the <b>total number of matching items</b>, not the
/// number on the current page — the front end computes the page count from it.
/// </summary>
public sealed record PagedResponse<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

/// <summary>
/// Normalizes paging input. Every list endpoint shares one set of boundary rules, so no endpoint
/// copies its own version that then drifts.
/// </summary>
public readonly record struct PageRequest(int Page, int PageSize)
{
    public const int DefaultPageSize = 20;
    public const int MaxPageSize = 100;

    /// <summary>
    /// Page numbers start at 1; the page size is clamped to [1, <see cref="MaxPageSize"/>] and
    /// defaults to <see cref="DefaultPageSize"/>.
    /// </summary>
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
