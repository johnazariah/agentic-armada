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
    public async Task Verifier_hashes_only_the_stream_opened_by_the_no_follow_boundary()
    {
        var original = """{"drill":"lab-001","result":"restored"}"""u8.ToArray();
        var evidence = new LocalRestoreEvidenceReference("/lab/restore-evidence.json", Digest(original));
        var opener = new RecordingArtifactOpener(new MemoryStream(original));
        var verifier = new LocalRestoreEvidenceVerifier(opener);

        Assert.True(await verifier.IsVerifiedAsync(evidence, CancellationToken.None));
        Assert.Equal(evidence.ArtifactPath, opener.ArtifactPath);

        var tamperedVerifier = new LocalRestoreEvidenceVerifier(
            new RecordingArtifactOpener(new MemoryStream("""{"drill":"lab-001","result":"tampered"}"""u8.ToArray())));

        Assert.False(await tamperedVerifier.IsVerifiedAsync(evidence, CancellationToken.None));
    }

    [Fact]
    public async Task Mac_no_follow_opener_rejects_symlinks_or_unsupported_platforms()
    {
        var opener = new MacNoFollowRestoreEvidenceArtifactOpener();
        if (!OperatingSystem.IsMacOS())
        {
            Assert.Null(await opener.TryOpenRegularFileAsync("/unsupported-platform", CancellationToken.None));
            return;
        }

        var directory = Path.Combine(Path.GetTempPath(), $"armada-host-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var target = Path.Combine(directory, "restore-evidence.json");
            var symlink = Path.Combine(directory, "replacement-link.json");
            await File.WriteAllTextAsync(target, """{"drill":"lab-001","result":"restored"}""");
            File.CreateSymbolicLink(symlink, target);

            Assert.NotNull(await opener.TryOpenRegularFileAsync(target, CancellationToken.None));
            Assert.Null(await opener.TryOpenRegularFileAsync(symlink, CancellationToken.None));
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

    private sealed class RecordingArtifactOpener(Stream stream) : IRestoreEvidenceArtifactOpener
    {
        public string? ArtifactPath { get; private set; }

        public ValueTask<Stream?> TryOpenRegularFileAsync(string artifactPath, CancellationToken cancellationToken)
        {
            ArtifactPath = artifactPath;
            return ValueTask.FromResult<Stream?>(stream);
        }
    }

    private static Armada.Contracts.Sha256Digest Digest(byte[] bytes) =>
        Armada.Contracts.Sha256Digest.Parse($"sha256:{Convert.ToHexStringLower(SHA256.HashData(bytes))}") switch
        {
            Armada.Contracts.Result<Armada.Contracts.Sha256Digest, Armada.Contracts.ContractValidationError>.Success success => success.Value,
            _ => throw new InvalidOperationException("Test digest creation failed.")
        };
}
