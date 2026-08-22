using System.Collections.Immutable;
using Armada.Contracts;
using Armada.NodeAgent;

namespace Armada.NodeAgent.Tests;

public sealed class ReleaseDistributionTests
{
    [Fact]
    public void Production_signing_and_verification_fail_closed_without_a_trusted_key_source()
    {
        var fixture = new ReleaseFixture();
        var canonical = ReleaseManifestContract.CanonicalBytes(fixture.Release.Manifest);

        var signing = new ProductionReleaseSigner(null).Sign(fixture.Release.Manifest, canonical);
        var verification = new ProductionReleaseVerifier(null).Verify(
            fixture.Release.Manifest,
            canonical,
            fixture.Release.Signature);

        Assert.Equal("trusted-key-source-unavailable", Failure(signing).Code);
        Assert.Equal("trusted-key-source-unavailable", Failure(verification).Code);
    }

    [Fact]
    public void Verification_requires_canonical_manifest_signature_and_exact_artifact_bytes()
    {
        var fixture = new ReleaseFixture();
        var tampered = fixture.Release with
        {
            Artifacts = fixture.Release.Artifacts.SetItem(
                0,
                fixture.Release.Artifacts[0] with { Bytes = "tampered"u8.ToArray().ToImmutableArray() })
        };

        var result = ReleaseVerification.Verify(tampered, fixture.Signer);

        Assert.Equal("release-artifact-digest-mismatch", Failure(result).Code);
    }

    [Fact]
    public void Valid_compatible_channel_pinned_release_plans_the_matching_platform_installer()
    {
        var fixture = new ReleaseFixture();
        var verified = Verified(fixture.Release, fixture.Signer);

        var plan = UpgradePlanning.Plan(fixture.State(), verified);

        var value = Success(plan);
        Assert.Equal(ReleaseComponent.NodeAgent, value.NodeAgentArtifact.Component);
        Assert.Equal(SupportedPlatform.MacOsArm64, value.InstallerArtifact.Platform);
        Assert.StartsWith("upgrade:sha256:", value.IdempotencyKey, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(ReleaseChannel.Beta, "release-channel-not-pinned")]
    [InlineData(ReleaseChannel.Canary, "release-revoked")]
    public void Channel_mismatch_and_revocation_are_refused(ReleaseChannel channel, string expectedCode)
    {
        var fixture = new ReleaseFixture();
        var manifest = fixture.Release.Manifest with
        {
            Channel = channel,
            Revocation = expectedCode == "release-revoked"
                ? new(true, fixture.Now, "compromised", "r-2")
                : fixture.Release.Manifest.Revocation
        };
        var release = fixture.Sign(manifest);

        var plan = UpgradePlanning.Plan(fixture.State(), Verified(release, fixture.Signer));

        Assert.Equal(expectedCode, Failure(plan).Code);
    }

    [Fact]
    public void Incompatible_platform_replay_downgrade_and_missing_anchor_are_refused()
    {
        var fixture = new ReleaseFixture();
        var verified = Verified(fixture.Release, fixture.Signer);
        var unsupported = fixture.State() with { Platform = SupportedPlatform.LinuxX64 };
        var replayed = fixture.State() with { SeenManifestDigests = ImmutableHashSet.Create(fixture.Release.ManifestDigest) };
        var downgrade = fixture.State() with { ActiveVersion = fixture.Release.Manifest.Version };
        var noAnchor = fixture.State() with { RollbackAnchor = null };

        Assert.Equal("release-platform-unsupported", Failure(UpgradePlanning.Plan(unsupported, verified)).Code);
        Assert.Equal("release-replay-refused", Failure(UpgradePlanning.Plan(replayed, verified)).Code);
        Assert.Equal("release-downgrade-refused", Failure(UpgradePlanning.Plan(downgrade, verified)).Code);
        Assert.Equal("rollback-anchor-missing", Failure(UpgradePlanning.Plan(noAnchor, verified)).Code);
    }

    [Fact]
    public void Incompatible_protocol_is_refused_before_staging()
    {
        var fixture = new ReleaseFixture();
        var incompatible = fixture.State() with { NodeProtocol = "armada.node/v1alpha2" };

        var result = UpgradePlanning.Plan(incompatible, Verified(fixture.Release, fixture.Signer));

        Assert.Equal("release-incompatible", Failure(result).Code);
    }

    [Fact]
    public async Task Failed_staging_does_not_confirm_health_activate_or_rollback_an_unstaged_release()
    {
        var fixture = new ReleaseFixture();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var staging = new RecordingStaging(stage: Failure<bool>("stage-failed", "The staging volume is unavailable."));
        var coordinator = new NodeUpgradeCoordinator(new InMemoryJournal(), staging, new FixedClock(fixture.Now));

        var result = await coordinator.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);

        Assert.Equal("stage-failed", Failure(result).Code);
        Assert.Equal(["stage"], staging.Operations);
    }

    [Fact]
    public async Task Health_failure_rolls_back_without_activation_and_records_the_failure()
    {
        var fixture = new ReleaseFixture();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var staging = new RecordingStaging(health: Failure<bool>("health-check-failed", "The staged agent did not become healthy."));
        var journal = new InMemoryJournal();
        var coordinator = new NodeUpgradeCoordinator(journal, staging, new FixedClock(fixture.Now));

        var result = await coordinator.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);
        var entries = Success(await journal.ReadAsync(CancellationToken.None));

        var value = Success(result);
        Assert.False(value.Activated);
        Assert.True(value.RolledBack);
        Assert.Equal(["stage", "health", "rollback"], staging.Operations);
        Assert.Equal([UpgradePhase.Staged, UpgradePhase.RolledBack], entries.Select(entry => entry.Upgrade!.Phase));
        Assert.Equal("health-check-failed", entries.Last().Upgrade!.Code);
    }

    [Fact]
    public async Task Activation_occurs_only_after_durable_health_confirmation()
    {
        var fixture = new ReleaseFixture();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var staging = new RecordingStaging();
        var journal = new InMemoryJournal();
        var coordinator = new NodeUpgradeCoordinator(journal, staging, new FixedClock(fixture.Now));

        var result = await coordinator.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);
        var entries = Success(await journal.ReadAsync(CancellationToken.None));
        var healthIndex = entries.ToList().FindIndex(entry => entry.Upgrade?.Phase == UpgradePhase.HealthConfirmed);

        Assert.True(Success(result).Activated);
        Assert.Equal(["stage", "health", "activate"], staging.Operations);
        Assert.Equal([UpgradePhase.Staged, UpgradePhase.HealthConfirmed, UpgradePhase.Activated], entries.Select(entry => entry.Upgrade!.Phase));
        Assert.True(healthIndex >= 0);
        Assert.Equal(UpgradePhase.Activated, entries.Last().Upgrade!.Phase);
    }

    [Fact]
    public async Task Failed_activation_rolls_back_and_replayed_execution_does_not_reactivate()
    {
        var fixture = new ReleaseFixture();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var staging = new RecordingStaging(activation: Failure<bool>("activate-failed", "Atomic activation failed."));
        var journal = new InMemoryJournal();
        var coordinator = new NodeUpgradeCoordinator(journal, staging, new FixedClock(fixture.Now));

        var failed = await coordinator.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);
        var retry = await coordinator.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);

        Assert.True(Success(failed).RolledBack);
        Assert.True(Success(retry).RolledBack);
        Assert.Equal(["stage", "health", "activate", "rollback"], staging.Operations);
    }

    [Fact]
    public async Task Activated_upgrade_is_idempotent_after_journal_replay()
    {
        var fixture = new ReleaseFixture();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var staging = new RecordingStaging();
        var journal = new InMemoryJournal();
        var coordinator = new NodeUpgradeCoordinator(journal, staging, new FixedClock(fixture.Now));

        await coordinator.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);
        var replay = await coordinator.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);

        Assert.Equal("upgrade-activated", Success(replay).Code);
        Assert.Equal(["stage", "health", "activate"], staging.Operations);
    }

    private static T Success<T, TFailure>(Result<T, TFailure> result) =>
        Assert.IsType<Result<T, TFailure>.Success>(result).Value;

    private static TFailure Failure<T, TFailure>(Result<T, TFailure> result) =>
        Assert.IsType<Result<T, TFailure>.Failure>(result).Error;

    private static VerifiedRelease Verified(SignedRelease release, IReleaseManifestVerifier verifier) =>
        Success(ReleaseVerification.Verify(release, verifier));

    private sealed class ReleaseFixture
    {
        private static readonly byte[] Key = [1, 3, 3, 7];

        public DateTimeOffset Now { get; } = DateTimeOffset.Parse("2026-08-23T00:00:00Z");
        public NodeDeviceIdentity Identity { get; } = new(ResourceId.New(), 3);
        public DeterministicTestReleaseSigner Signer { get; } = new("test-key", Key);
        public SignedRelease Release { get; }

        public ReleaseFixture()
        {
            var artifacts = new[]
            {
                Artifact(ReleaseComponent.ControlPlane, null, "control-plane.tar.gz", "control-plane"u8),
                Artifact(ReleaseComponent.NodeAgent, null, "node-agent.tar.gz", "node-agent"u8),
                Artifact(ReleaseComponent.Installer, SupportedPlatform.MacOsArm64, "armada.pkg", "installer"u8),
                Artifact(ReleaseComponent.Installer, SupportedPlatform.WindowsX64, "armada.msi", "windows-installer"u8)
            };
            Release = Sign(new(
                ReleaseManifestContract.SchemaVersion,
                "r-2",
                new ReleaseVersion(1, 1, 0),
                ReleaseChannel.Canary,
                Now,
                "test-key",
                new(
                    NodeAgentProtocol.Version,
                    NodeAgentProtocol.Version,
                    "armada.control/v1alpha1",
                    "armada.control/v1alpha1"),
                new(false, null, null, null),
                new("r-1", Digest("previous"u8)),
                artifacts.Select(static value => value.Artifact).ToImmutableArray()),
                artifacts);
        }

        public NodeUpgradeState State() =>
            new(
                SupportedPlatform.MacOsArm64,
                NodeAgentProtocol.Version,
                "armada.control/v1alpha1",
                ReleaseChannel.Canary,
                "r-1",
                new ReleaseVersion(1, 0, 0),
                Digest("active"u8),
                new UpgradeRollbackAnchor("r-1", new ReleaseVersion(1, 0, 0), Digest("previous"u8)),
                ImmutableHashSet<Sha256Digest>.Empty);

        public SignedRelease Sign(ReleaseManifest manifest) =>
            Sign(
                manifest,
                manifest.Artifacts.Select(artifact =>
                    new ReleaseArtifactPayload(artifact, artifact.Name switch
                    {
                        "control-plane.tar.gz" => "control-plane"u8.ToArray().ToImmutableArray(),
                        "node-agent.tar.gz" => "node-agent"u8.ToArray().ToImmutableArray(),
                        "armada.pkg" => "installer"u8.ToArray().ToImmutableArray(),
                        _ => "windows-installer"u8.ToArray().ToImmutableArray()
                    })).ToArray());

        private SignedRelease Sign(ReleaseManifest manifest, IEnumerable<ReleaseArtifactPayload> artifacts)
        {
            var canonical = ReleaseManifestContract.CanonicalBytes(manifest);
            return new(
                manifest,
                ReleaseManifestContract.Digest(canonical),
                Success(Signer.Sign(manifest, canonical)),
                artifacts.ToImmutableArray());
        }

        private static ReleaseArtifactPayload Artifact(
            ReleaseComponent component,
            SupportedPlatform? platform,
            string name,
            ReadOnlySpan<byte> bytes)
        {
            var artifact = new ReleaseArtifact(
                component,
                platform,
                name,
                Digest(bytes),
                "armada.artifact/v1",
                NodeAgentProtocol.Version);
            return new(artifact, bytes.ToArray().ToImmutableArray());
        }

        private static Sha256Digest Digest(ReadOnlySpan<byte> bytes) =>
            ReleaseManifestContract.Digest(bytes.ToArray().ToImmutableArray());
    }

    private sealed class RecordingStaging(
        Result<bool, UpgradeFailure>? stage = null,
        Result<bool, UpgradeFailure>? health = null,
        Result<bool, UpgradeFailure>? activation = null,
        Result<bool, UpgradeFailure>? rollback = null) : IUpgradeStaging
    {
        public List<string> Operations { get; } = [];

        public Task<Result<bool, UpgradeFailure>> StageAsync(UpgradePlan plan, CancellationToken cancellationToken)
        {
            Operations.Add("stage");
            return Task.FromResult(stage ?? Success<bool, UpgradeFailure>(true));
        }

        public Task<Result<bool, UpgradeFailure>> ConfirmHealthAsync(UpgradePlan plan, CancellationToken cancellationToken)
        {
            Operations.Add("health");
            return Task.FromResult(health ?? Success<bool, UpgradeFailure>(true));
        }

        public Task<Result<bool, UpgradeFailure>> ActivateAsync(UpgradePlan plan, CancellationToken cancellationToken)
        {
            Operations.Add("activate");
            return Task.FromResult(activation ?? Success<bool, UpgradeFailure>(true));
        }

        public Task<Result<bool, UpgradeFailure>> RollbackAsync(UpgradePlan plan, CancellationToken cancellationToken)
        {
            Operations.Add("rollback");
            return Task.FromResult(rollback ?? Success<bool, UpgradeFailure>(true));
        }

        private static Result<T, TFailure> Success<T, TFailure>(T value) =>
            new Result<T, TFailure>.Success(value);
    }

    private static Result<T, UpgradeFailure> Failure<T>(string code, string message) =>
        new Result<T, UpgradeFailure>.Failure(new(code, message));
}
