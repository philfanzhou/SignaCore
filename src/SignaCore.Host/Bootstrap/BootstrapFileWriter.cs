using System.Text;
using System.Text.Json;
using SignaCore.Database;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// Writes <c>signacore.bootstrap.json</c>.
/// <para>
/// The file is the deployment's only copy of the external root key, so the write must never be able
/// to destroy a working bootstrap: the content goes to a temporary file in the same directory, is
/// flushed to the storage device, is given restrictive permissions, and only then atomically
/// replaces the target. An interrupted write leaves the previous valid file intact.
/// </para>
/// </summary>
internal static class BootstrapFileWriter
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true
    };

    private const UnixFileMode SecretFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private const UnixFileMode SecretDirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    public static void Write(string filePath, DatabaseOptions database, string masterKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentNullException.ThrowIfNull(database);
        ArgumentException.ThrowIfNullOrWhiteSpace(masterKey);

        var fullPath = Path.GetFullPath(filePath);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new BootstrapException(
                $"'{filePath}' does not name a directory the bootstrap file can be written to.");

        EnsureDirectory(directory);

        var payload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(
            new BootstrapFile
            {
                Database = new BootstrapDatabaseSection
                {
                    Provider = database.Provider,
                    ServerVersion = database.ServerVersion,
                    ConnectionString = database.ConnectionString
                },
                MasterKey = masterKey
            },
            SerializerOptions));

        // The temporary file has to share the directory: a rename is only atomic within one volume,
        // and a cross-volume move would fall back to a copy that can be observed half-written.
        var temporaryPath = Path.Combine(directory, $".{FileNameOf(fullPath)}.{Guid.NewGuid():N}.tmp");

        try
        {
            using (var stream = OpenSecretFile(temporaryPath))
            {
                SetUnixFileMode(temporaryPath, SecretFileMode);
                stream.Write(payload);
                // Without an explicit device flush, a host that loses power right after the rename
                // can come back with the directory entry present and the content empty.
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, fullPath, overwrite: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            DeleteQuietly(temporaryPath);
            throw new BootstrapException(
                $"The SignaCore bootstrap file at '{fullPath}' could not be written: " +
                $"{exception.Message} Mount the configuration directory read-write and make sure it " +
                "is owned by the SignaCore runtime identity.",
                exception);
        }
        catch
        {
            DeleteQuietly(temporaryPath);
            throw;
        }
    }

    private static void EnsureDirectory(string directory)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(directory);
            }
            else
            {
                Directory.CreateDirectory(directory, SecretDirectoryMode);
            }
            SetUnixFileMode(directory, SecretDirectoryMode);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new BootstrapException(
                $"The configuration directory '{directory}' could not be created: {exception.Message}",
                exception);
        }
    }

    private static string FileNameOf(string fullPath) =>
        Path.GetFileName(fullPath) is { Length: > 0 } name ? name : BootstrapLoader.FileName;

    private static FileStream OpenSecretFile(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        }

        return new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = SecretFileMode
        });
    }

    private static void SetUnixFileMode(string path, UnixFileMode mode)
    {
        if (OperatingSystem.IsWindows())
        {
            // Windows uses ACLs inherited from the directory; there is no chmod equivalent to apply.
            return;
        }

        File.SetUnixFileMode(path, mode);
    }

    private static void DeleteQuietly(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Leaving a stray temporary file behind is strictly better than masking the real error.
        }
    }
}
