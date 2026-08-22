using Armada.ControlPlane.Host;
using System.Security.Cryptography;

namespace Armada.ControlPlane.Host.Tests;

public sealed class ControlPlaneReadinessTests
{
    [Fact]
    public async Task Invalid_configuration_is_not_ready_and_does_not_probe_postgres()
    {
        var probe = new RecordingProbe(isReachable: true);
        var readiness = new ControlPlaneReadiness(new(), new RecordingEvidenceVerifier(isVerified: true), probe);

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
        var readiness = new ControlPlaneReadiness(
            ControlPlaneConfigurationTests.ValidOptions(),
            new RecordingEvidenceVerifier(isVerified: true),
            probe);

        var report = await readiness.CheckAsync(CancellationToken.None);

        Assert.True(report.IsReady);
        Assert.Collection(
            report.Checks,
            check => Assert.Equal(new ReadinessCheck("configuration", true), check),
            check => Assert.Equal(new ReadinessCheck("restore-evidence", true), check),
            check => Assert.Equal(new ReadinessCheck("postgres", true), check));
        Assert.Equal(1, probe.CallCount);
    }

    [Fact]
    public async Task Unreachable_postgres_is_not_ready()
    {
        var probe = new RecordingProbe(isReachable: false);
        var readiness = new ControlPlaneReadiness(
            ControlPlaneConfigurationTests.ValidOptions(),
            new RecordingEvidenceVerifier(isVerified: true),
            probe);

        var report = await readiness.CheckAsync(CancellationToken.None);

        Assert.False(report.IsReady);
        Assert.Collection(
            report.Checks,
            check => Assert.Equal(new ReadinessCheck("configuration", true), check),
            check => Assert.Equal(new ReadinessCheck("restore-evidence", true), check),
            check => Assert.Equal(new ReadinessCheck("postgres", false), check));
    }

    [Fact]
    public async Task Unverified_restore_evidence_is_not_ready_and_does_not_probe_postgres()
    {
        var evidence = new RecordingEvidenceVerifier(isVerified: false);
        var probe = new RecordingProbe(isReachable: true);
        var readiness = new ControlPlaneReadiness(
            ControlPlaneConfigurationTests.ValidOptions(),
            evidence,
            probe);

        var report = await readiness.CheckAsync(CancellationToken.None);

        Assert.False(report.IsReady);
        Assert.Collection(
            report.Checks,
            check => Assert.Equal(new ReadinessCheck("configuration", true), check),
            check => Assert.Equal(new ReadinessCheck("restore-evidence", false), check));
        Assert.Equal(1, evidence.CallCount);
        Assert.Equal(0, probe.CallCount);
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

    [Fact]
    public async Task Local_restore_evidence_rejects_missing_directory_and_tampered_artifacts()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"armada-host-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "restore-evidence.json");
            await File.WriteAllTextAsync(path, """{"drill":"lab-001","result":"restored"}""");
            var expectedDigest = Digest(await File.ReadAllBytesAsync(path));
            var verifier = new LocalRestoreEvidenceVerifier();

            Assert.True(await verifier.IsVerifiedAsync(new(path, expectedDigest), CancellationToken.None));
            Assert.False(await verifier.IsVerifiedAsync(new(Path.Combine(directory, "missing.json"), expectedDigest), CancellationToken.None));
            Assert.False(await verifier.IsVerifiedAsync(new(directory, expectedDigest), CancellationToken.None));

            await File.WriteAllTextAsync(path, """{"drill":"lab-001","result":"tampered"}""");

            Assert.False(await verifier.IsVerifiedAsync(new(path, expectedDigest), CancellationToken.None));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
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

    private sealed class RecordingEvidenceVerifier(bool isVerified) : IRestoreEvidenceVerifier
    {
        public int CallCount { get; private set; }

        public Task<bool> IsVerifiedAsync(LocalRestoreEvidenceReference evidence, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(isVerified);
        }
    }

    private static Armada.Contracts.Sha256Digest Digest(byte[] bytes) =>
        Armada.Contracts.Sha256Digest.Parse($"sha256:{Convert.ToHexStringLower(SHA256.HashData(bytes))}") switch
        {
            Armada.Contracts.Result<Armada.Contracts.Sha256Digest, Armada.Contracts.ContractValidationError>.Success success => success.Value,
            _ => throw new InvalidOperationException("Test digest creation failed.")
        };
}
