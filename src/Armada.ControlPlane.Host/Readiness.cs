using System.Collections.Immutable;
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
    public async Task<bool> IsVerifiedAsync(LocalRestoreEvidenceReference evidence, CancellationToken cancellationToken)
    {
        var file = new FileInfo(evidence.ArtifactPath);
        if (!file.Exists ||
            (file.Attributes & FileAttributes.Directory) != 0 ||
            file.LinkTarget is not null)
        {
            return false;
        }

        try
        {
            await using var stream = new FileStream(
                file.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
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
