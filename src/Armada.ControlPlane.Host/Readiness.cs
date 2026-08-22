using System.Collections.Immutable;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Npgsql;

namespace Armada.ControlPlane.Host;

public sealed record ReadinessCheck(string Name, bool Passed);

public sealed record ReadinessReport(bool IsReady, ImmutableArray<ReadinessCheck> Checks);

public interface IControlPlaneReadiness
{
    Task<ReadinessReport> CheckAsync(CancellationToken cancellationToken);
}

public interface IPostgresReadinessProbe
{
    Task<bool> IsReachableAsync(CancellationToken cancellationToken);
}

public interface IRestoreEvidenceVerifier
{
    Task<bool> IsVerifiedAsync(LocalRestoreEvidenceReference evidence, CancellationToken cancellationToken);
}

public interface IRestoreEvidenceArtifactOpener
{
    ValueTask<Stream?> TryOpenRegularFileAsync(string artifactPath, CancellationToken cancellationToken);
}

public sealed class ControlPlaneReadiness(
    ControlPlaneOptions options,
    IRestoreEvidenceVerifier restoreEvidence,
    IPostgresReadinessProbe postgres) : IControlPlaneReadiness
{
    public async Task<ReadinessReport> CheckAsync(CancellationToken cancellationToken)
    {
        var configurationFailures = ControlPlaneConfiguration.Validate(options);
        if (!configurationFailures.IsEmpty)
        {
            return new(
                IsReady: false,
                [new("configuration", false)]);
        }

        if (!ControlPlaneConfiguration.TryGetRestoreEvidenceReference(options.Storage.Backup, out var evidence) ||
            !await restoreEvidence.IsVerifiedAsync(evidence, cancellationToken))
        {
            return new(
                IsReady: false,
                [new("configuration", true), new("restore-evidence", false)]);
        }

        var postgresReady = await postgres.IsReachableAsync(cancellationToken);
        return new(
            IsReady: postgresReady,
            [new("configuration", true), new("restore-evidence", true), new("postgres", postgresReady)]);
    }
}

public sealed class PostgresReadinessProbe(ControlPlaneOptions options) : IPostgresReadinessProbe, IAsyncDisposable
{
    private readonly Lazy<NpgsqlDataSource> dataSource = new(
        () => NpgsqlDataSource.Create(options.Postgres.ConnectionString),
        LazyThreadSafetyMode.ExecutionAndPublication);

    public async Task<bool> IsReachableAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = await dataSource.Value.OpenConnectionAsync(cancellationToken);
            await using var command = new NpgsqlCommand("SELECT 1;", connection);
            return await command.ExecuteScalarAsync(cancellationToken) is 1;
        }
        catch (NpgsqlException)
        {
            return false;
        }
        catch (TimeoutException)
        {
            return false;
        }
    }

    public ValueTask DisposeAsync() =>
        dataSource.IsValueCreated ? dataSource.Value.DisposeAsync() : ValueTask.CompletedTask;
}

public sealed class LocalRestoreEvidenceVerifier : IRestoreEvidenceVerifier
{
    private readonly IRestoreEvidenceArtifactOpener opener;

    public LocalRestoreEvidenceVerifier()
        : this(new MacNoFollowRestoreEvidenceArtifactOpener())
    {
    }

    public LocalRestoreEvidenceVerifier(IRestoreEvidenceArtifactOpener opener)
    {
        this.opener = opener ?? throw new ArgumentNullException(nameof(opener));
    }

    public async Task<bool> IsVerifiedAsync(LocalRestoreEvidenceReference evidence, CancellationToken cancellationToken)
    {
        await using var stream = await opener.TryOpenRegularFileAsync(evidence.ArtifactPath, cancellationToken);
        if (stream is null)
        {
            return false;
        }

        try
        {
            var hash = await SHA256.HashDataAsync(stream, cancellationToken);
            return string.Equals(
                $"sha256:{Convert.ToHexStringLower(hash)}",
                evidence.ContentDigest.Value,
                StringComparison.Ordinal);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }
}

public sealed class MacNoFollowRestoreEvidenceArtifactOpener : IRestoreEvidenceArtifactOpener
    {
        private const int OpenReadOnly = 0;
        private const int OpenNonBlocking = 0x0004;
        private const int OpenNoFollow = 0x0100;
        private const int OpenCloseOnExec = 0x01000000;
        private const ushort FileTypeMask = 0xf000;
        private const ushort RegularFileType = 0x8000;

        public ValueTask<Stream?> TryOpenRegularFileAsync(string artifactPath, CancellationToken cancellationToken)
        {
            if (!OperatingSystem.IsMacOS() || cancellationToken.IsCancellationRequested)
            {
                return ValueTask.FromResult<Stream?>(null);
            }

            var fileDescriptor = Open(
                artifactPath,
                OpenReadOnly | OpenNonBlocking | OpenNoFollow | OpenCloseOnExec);
            if (fileDescriptor < 0)
            {
                return ValueTask.FromResult<Stream?>(null);
            }

            var handle = new SafeFileHandle((nint)fileDescriptor, ownsHandle: true);
            if (GetFileStatus(fileDescriptor, out var status) != 0 ||
                (status.Mode & FileTypeMask) != RegularFileType)
            {
                handle.Dispose();
                return ValueTask.FromResult<Stream?>(null);
            }

            return ValueTask.FromResult<Stream?>(
                new FileStream(handle, FileAccess.Read, bufferSize: 4096, isAsync: false));
        }

        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "open", SetLastError = true)]
        private static extern int Open(string path, int flags);

        [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fstat", SetLastError = true)]
        private static extern int GetFileStatus(int fileDescriptor, out MacFileStatus status);

        [StructLayout(LayoutKind.Sequential)]
        private struct MacFileStatus
        {
            public int Device;
            public ushort Mode;
            public ushort LinkCount;
            public ulong Inode;
            public uint UserId;
            public uint GroupId;
            public int DeviceType;
            public long AccessSeconds;
            public long AccessNanoseconds;
            public long ModificationSeconds;
            public long ModificationNanoseconds;
            public long ChangeSeconds;
            public long ChangeNanoseconds;
            public long BirthSeconds;
            public long BirthNanoseconds;
            public long Size;
            public long Blocks;
            public int BlockSize;
            public uint Flags;
            public uint Generation;
            public int Reserved;
            public long SpareOne;
            public long SpareTwo;
        }
}
