using System.Text.Json;

namespace SignaCore.Client.AspNetCore;

/// <summary>Thrown when a backchannel response body exceeds its configured byte ceiling.</summary>
internal sealed class SignaCoreResponseLimitException : Exception;

/// <summary>
/// The shared reader of the package's backchannel JSON responses: the body is read under a byte
/// ceiling, and the top-level object must not repeat a member name — <see cref="JsonDocument"/>
/// keeps duplicate members and parsers disagree about which value wins, so a crafted response
/// with duplicates is refused outright rather than interpreted.
/// </summary>
internal static class SignaCoreBoundedJson
{
    /// <summary>
    /// Parses one JSON document from a stream under a byte ceiling. Throws
    /// <see cref="SignaCoreResponseLimitException"/> when the body exceeds the ceiling,
    /// <see cref="JsonException"/> on malformed JSON or (when requested) duplicated top-level
    /// member names. The returned document is owned by the caller.
    /// </summary>
    internal static async Task<JsonDocument> ParseAsync(
        Stream stream,
        long maxBytes,
        bool rejectDuplicateMembers,
        CancellationToken cancellationToken)
    {
        await using var bounded = new BoundedStream(stream, maxBytes);
        var document = await JsonDocument.ParseAsync(bounded, cancellationToken: cancellationToken);
        if (rejectDuplicateMembers
            && document.RootElement.ValueKind == JsonValueKind.Object
            && HasDuplicateMembers(document.RootElement))
        {
            document.Dispose();
            throw new JsonException("The response object repeats a top-level member name.");
        }

        return document;
    }

    private static bool HasDuplicateMembers(JsonElement root)
    {
        HashSet<string> seen = new(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!seen.Add(property.Name))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>A read-through stream that fails closed once more than the ceiling has been
    /// read, so an oversized body is never fully buffered.</summary>
    private sealed class BoundedStream(Stream inner, long maxBytes) : Stream
    {
        private long _read;

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await inner.ReadAsync(buffer, cancellationToken);
            Count(read);
            return read;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = inner.Read(buffer, offset, count);
            Count(read);
            return read;
        }

        private void Count(int read)
        {
            _read += read;
            if (_read > maxBytes)
            {
                throw new SignaCoreResponseLimitException();
            }
        }

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
