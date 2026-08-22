using System.Collections.Immutable;
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

public sealed class ControlPlaneReadiness(
    ControlPlaneOptions options,
    IPostgresReadinessProbe postgres,
    TimeProvider timeProvider) : IControlPlaneReadiness
{
    public async Task<ReadinessReport> CheckAsync(CancellationToken cancellationToken)
    {
        var configurationFailures = ControlPlaneConfiguration.Validate(options, timeProvider.GetUtcNow());
        if (!configurationFailures.IsEmpty)
        {
            return new(
                IsReady: false,
                [new("configuration", false)]);
        }

        var postgresReady = await postgres.IsReachableAsync(cancellationToken);
        return new(
            IsReady: postgresReady,
            [new("configuration", true), new("postgres", postgresReady)]);
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
