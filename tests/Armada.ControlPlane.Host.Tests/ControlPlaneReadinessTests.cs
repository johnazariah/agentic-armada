using Armada.ControlPlane.Host;

namespace Armada.ControlPlane.Host.Tests;

public sealed class ControlPlaneReadinessTests
{
    private static readonly TimeProvider Clock = new FixedTimeProvider(
        new DateTimeOffset(2026, 8, 23, 0, 0, 0, TimeSpan.Zero));

    [Fact]
    public async Task Invalid_configuration_is_not_ready_and_does_not_probe_postgres()
    {
        var probe = new RecordingProbe(isReachable: true);
        var readiness = new ControlPlaneReadiness(new(), probe, Clock);

        var report = await readiness.CheckAsync(CancellationToken.None);

        Assert.False(report.IsReady);
        Assert.Collection(
            report.Checks,
            check => Assert.Equal(new ReadinessCheck("configuration", false), check));
        Assert.Equal(0, probe.CallCount);
    }

    [Fact]
    public async Task Valid_configuration_and_reachable_postgres_are_ready()
    {
        var probe = new RecordingProbe(isReachable: true);
        var readiness = new ControlPlaneReadiness(ControlPlaneConfigurationTests.ValidOptions(), probe, Clock);

        var report = await readiness.CheckAsync(CancellationToken.None);

        Assert.True(report.IsReady);
        Assert.Collection(
            report.Checks,
            check => Assert.Equal(new ReadinessCheck("configuration", true), check),
            check => Assert.Equal(new ReadinessCheck("postgres", true), check));
        Assert.Equal(1, probe.CallCount);
    }

    [Fact]
    public async Task Unreachable_postgres_is_not_ready()
    {
        var probe = new RecordingProbe(isReachable: false);
        var readiness = new ControlPlaneReadiness(ControlPlaneConfigurationTests.ValidOptions(), probe, Clock);

        var report = await readiness.CheckAsync(CancellationToken.None);

        Assert.False(report.IsReady);
        Assert.Collection(
            report.Checks,
            check => Assert.Equal(new ReadinessCheck("configuration", true), check),
            check => Assert.Equal(new ReadinessCheck("postgres", false), check));
    }

    [Fact]
    public async Task Concrete_postgres_probe_fails_closed_when_local_database_is_unreachable()
    {
        var options = ControlPlaneConfigurationTests.ValidOptions() with
        {
            Postgres = new()
            {
                ConnectionString = "Host=127.0.0.1;Port=1;Database=armada_lab;Username=armada_lab;Timeout=1;Pooling=false"
            }
        };
        await using var probe = new PostgresReadinessProbe(options);

        var isReachable = await probe.IsReachableAsync(CancellationToken.None);

        Assert.False(isReachable);
    }

    private sealed class RecordingProbe(bool isReachable) : IPostgresReadinessProbe
    {
        public int CallCount { get; private set; }

        public Task<bool> IsReachableAsync(CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(isReachable);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
