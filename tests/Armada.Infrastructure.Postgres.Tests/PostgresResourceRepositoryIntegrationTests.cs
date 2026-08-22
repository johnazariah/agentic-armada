using System.Collections.Immutable;
using Armada.Application;
using Armada.Contracts;
using Npgsql;

namespace Armada.Infrastructure.Postgres.Tests;

[CollectionDefinition("postgres-integration", DisableParallelization = true)]
public sealed class PostgresIntegrationCollection;

[Collection("postgres-integration")]
public sealed class PostgresResourceRepositoryIntegrationTests : IAsyncLifetime
{
    private const string ConnectionVariable = "ARMADA_POSTGRES_CONNECTION";
    private NpgsqlDataSource? dataSource;
    private PostgresResourceRepository? repository;

    public async Task InitializeAsync()
    {
        var connectionString = Environment.GetEnvironmentVariable(ConnectionVariable);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                $"{ConnectionVariable} is required for PostgreSQL integration tests. " +
                "Start PostgreSQL with `docker run --rm --name armada-postgres -e POSTGRES_DB=armada " +
                "-e POSTGRES_USER=armada -e POSTGRES_PASSWORD=armada -p 5432:5432 postgres:16` and set " +
                $"{ConnectionVariable}=Host=localhost;Port=5432;Database=armada;Username=armada;Password=armada.");
        }

        dataSource = NpgsqlDataSource.Create(connectionString);
        var migrator = new PostgresMigrationRunner(dataSource);
        await migrator.ApplyAsync(Now, CancellationToken.None);
        await migrator.ApplyAsync(Now, CancellationToken.None);
        repository = new PostgresResourceRepository(dataSource);
    }

    public Task DisposeAsync()
    {
        dataSource?.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Migration_is_idempotent_and_records_the_schema_version()
    {
        await ResetAsync();

        await using var connection = await Source.OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            "SELECT COUNT(*) FROM armada_schema_migrations WHERE version = 1;",
            connection);

        Assert.Equal(1L, (long)(await command.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task Concurrent_CAS_updates_commit_once_with_atomic_ledger_and_outbox()
    {
        await ResetAsync();
        var project = Project();
        var create = CreateCommit(project);
        Assert.IsType<ResourceStoreResult.Committed>(await Repository.CreateAsync(create, CancellationToken.None));
        var current = (await Repository.GetAsync(project.Metadata.Uid, CancellationToken.None))!;
        var first = UpdateCommit(current, 1);
        var second = UpdateCommit(current, 2);

        var results = await Task.WhenAll(
            Repository.CompareAndSwapAsync(first, current.ResourceVersion, CancellationToken.None),
            Repository.CompareAndSwapAsync(second, current.ResourceVersion, CancellationToken.None));

        Assert.Equal(1, results.Count(static result => result is ResourceStoreResult.Committed));
        Assert.Equal(1, results.Count(static result => result is ResourceStoreResult.Conflict));
        Assert.Equal(2L, await CountAsync("armada_event_ledger"));
        Assert.Equal(2L, await CountAsync("armada_outbox"));
    }

    [Fact]
    public async Task Concurrent_identical_create_returns_the_original_durable_commit()
    {
        await ResetAsync();
        var commit = CreateCommit(Project());
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var deliveries = Enumerable.Range(0, 2)
            .Select(async _ =>
            {
                await start.Task;
                return await Repository.CreateAsync(commit, CancellationToken.None);
            })
            .ToArray();

        start.SetResult();
        var results = await Task.WhenAll(deliveries);

        Assert.Equal(1, results.Count(static result => result is ResourceStoreResult.Committed));
        var replay = Assert.IsType<ResourceStoreResult.AlreadyApplied>(
            Assert.Single(results, static result => result is ResourceStoreResult.AlreadyApplied));
        Assert.Equal(commit.Resource.ResourceVersion, replay.Commit.Resource.ResourceVersion);
        Assert.Equal(1L, await CountAsync("armada_event_ledger"));
        Assert.Equal(1L, await CountAsync("armada_outbox"));
    }

    [Fact]
    public async Task Idempotency_lookup_returns_the_original_snapshot_after_later_updates()
    {
        await ResetAsync();
        var project = Project();
        Assert.IsType<ResourceStoreResult.Committed>(await Repository.CreateAsync(CreateCommit(project), CancellationToken.None));
        var firstCurrent = (await Repository.GetAsync(project.Metadata.Uid, CancellationToken.None))!;
        var firstUpdate = UpdateCommit(firstCurrent, 1);
        Assert.IsType<ResourceStoreResult.Committed>(
            await Repository.CompareAndSwapAsync(firstUpdate, firstCurrent.ResourceVersion, CancellationToken.None));
        var secondCurrent = (await Repository.GetAsync(project.Metadata.Uid, CancellationToken.None))!;
        var secondUpdate = UpdateCommit(secondCurrent, 2);
        Assert.IsType<ResourceStoreResult.Committed>(
            await Repository.CompareAndSwapAsync(secondUpdate, secondCurrent.ResourceVersion, CancellationToken.None));

        var replay = (await Repository.FindByIdempotencyKeyAsync(
            firstUpdate.LedgerEvent.IdempotencyKey,
            CancellationToken.None))!;

        Assert.Equal("2", replay.Resource.ResourceVersion.Value);
        Assert.Equal(1m, V1Alpha1Json.DeserializeProject(replay.Resource.Document.GetRawText())
            .AsSuccess().Spec.BudgetLimit);
        Assert.Equal("3", (await Repository.GetAsync(project.Metadata.Uid, CancellationToken.None))!.ResourceVersion.Value);
    }

    private NpgsqlDataSource Source => dataSource ?? throw new InvalidOperationException("The PostgreSQL data source was not initialised.");
    private PostgresResourceRepository Repository => repository ?? throw new InvalidOperationException("The PostgreSQL repository was not initialised.");

    private async Task ResetAsync()
    {
        await using var connection = await Source.OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            "TRUNCATE armada_outbox, armada_event_ledger, armada_current_resources;",
            connection);
        await command.ExecuteNonQueryAsync();
    }

    private async Task<long> CountAsync(string table)
    {
        await using var connection = await Source.OpenConnectionAsync();
        await using var command = new NpgsqlCommand($"SELECT COUNT(*) FROM {table};", connection);
        return (long)(await command.ExecuteScalarAsync())!;
    }

    private static ResourceCommit CreateCommit(Project project) =>
        ResourceCommandDecisions.Create(
            new CreateResourceCommand(project, new ActorId("api-user"), Guid.NewGuid(), null, Now))
        .AsSuccess();

    private static ResourceCommit UpdateCommit(PersistedResource current, int budget) =>
        ResourceCommandDecisions.UpdateSpec(
            current,
            new UpdateResourceSpecCommand(
                current.Id,
                current.ResourceVersion,
                TransitionId.New(),
                ProjectSpec(budget),
                new ActorId("api-user"),
                Guid.NewGuid(),
                null,
                Now.AddMinutes(budget)))
        .AsSuccess();

    private static Project Project() =>
        new(
            Metadata(),
            ProjectSpec(0),
            new ProjectStatus(new ResourceStatus(0, []), null));

    private static ProjectSpec ProjectSpec(int budget) =>
        new(
            [GitHubRepository("johnazariah/agentic-armada")],
            new GitHubReleaseEvidenceArchiveProfile(GitHubRepository("johnazariah/armada-evidence")),
            new GitHubCopilotSessionProfile(Digest('a')),
            Digest('b'),
            budget == 0 ? null : budget);

    private static ResourceMetadata Metadata() =>
        new(
            ResourceId.New(),
            new OrganisationId(Guid.NewGuid()),
            null,
            "postgres-project",
            new ResourceVersion("1"),
            1,
            ImmutableDictionary<string, string>.Empty,
            ImmutableDictionary<string, string>.Empty,
            ImmutableArray<OwnerReference>.Empty,
            ImmutableArray<string>.Empty,
            Now,
            Now);

    private static RepositoryName GitHubRepository(string value) =>
        global::Armada.Contracts.RepositoryName.Parse(value).AsSuccess();

    private static Sha256Digest Digest(char character) =>
        Sha256Digest.Parse($"sha256:{new string(character, 64)}").AsSuccess();

    private static readonly DateTimeOffset Now = new(2026, 8, 23, 0, 0, 0, TimeSpan.Zero);
}

internal static class ResultAssertions
{
    public static T AsSuccess<T>(this Result<T, ContractValidationError> result) =>
        Assert.IsType<Result<T, ContractValidationError>.Success>(result).Value;

    public static T AsSuccess<T>(this Result<T, ResourceCommandFailure> result) =>
        Assert.IsType<Result<T, ResourceCommandFailure>.Success>(result).Value;
}
