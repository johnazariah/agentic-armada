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
    public void Verification_rejects_hostile_null_record_shapes_without_throwing()
    {
        var fixture = new ReleaseFixture();
        var missingSignature = fixture.Release with { Signature = null! };
        var missingVersion = fixture.Release with
        {
            Manifest = fixture.Release.Manifest with { Version = null! }
        };

        var signatureException = Record.Exception(() => ReleaseVerification.Verify(missingSignature, fixture.Signer));
        var versionException = Record.Exception(() => ReleaseVerification.Verify(missingVersion, fixture.Signer));
        var signatureResult = ReleaseVerification.Verify(missingSignature, fixture.Signer);
        var versionResult = ReleaseVerification.Verify(missingVersion, fixture.Signer);

        Assert.Null(signatureException);
        Assert.Null(versionException);
        Assert.Equal("invalid-signed-release", Failure(signatureResult).Code);
        Assert.Equal("invalid-release-manifest", Failure(versionResult).Code);
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
    public async Task Failed_staging_is_treated_as_partially_mutated_and_rolls_back_before_returning()
    {
        var fixture = new ReleaseFixture();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var staging = new RecordingStaging(
            stage: Failure<bool>("stage-failed", "The staging volume is unavailable."),
            stageLeavesStagedOnFailure: true);
        var coordinator = new NodeUpgradeCoordinator(new InMemoryJournal(), staging, new FixedClock(fixture.Now));

        var result = await coordinator.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);

        Assert.True(Success(result).RolledBack);
        Assert.Equal("stage-failed", Success(result).Code);
        Assert.Equal(["stage", "rollback"], staging.Operations);
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
        Assert.Equal(
            [
                UpgradePhase.StageClaimed,
                UpgradePhase.StageClaimed,
                UpgradePhase.Staged,
                UpgradePhase.HealthClaimed,
                UpgradePhase.HealthClaimed,
                UpgradePhase.RollbackClaimed,
                UpgradePhase.RollbackClaimed,
                UpgradePhase.RolledBack
            ],
            entries.Select(entry => entry.Upgrade!.Phase));
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
        Assert.Equal(
            [
                UpgradePhase.StageClaimed,
                UpgradePhase.StageClaimed,
                UpgradePhase.Staged,
                UpgradePhase.HealthClaimed,
                UpgradePhase.HealthClaimed,
                UpgradePhase.HealthConfirmed,
                UpgradePhase.ActivationClaimed,
                UpgradePhase.ActivationClaimed,
                UpgradePhase.Activated
            ],
            entries.Select(entry => entry.Upgrade!.Phase));
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

    [Fact]
    public async Task Upgrade_claims_are_atomic_across_multiple_coordinator_instances_and_node_writers()
    {
        var fixture = new ReleaseFixture();
        var journal = new InMemoryJournal();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var first = Transition(fixture, plan, UpgradePhase.StageClaimed, fixture.Now, fixture.Now.AddMinutes(5));
        var second = first with { OperationId = Guid.NewGuid() };
        var claims = await Task.WhenAll(
            journal.ClaimUpgradeTransitionAsync(fixture.Identity, first, CancellationToken.None),
            journal.ClaimUpgradeTransitionAsync(fixture.Identity, second, CancellationToken.None));

        var boundary = fixture.Boundary(journal);
        await boundary.ReceiveAsync(fixture.StartEnvelope(sequence: 1), CancellationToken.None);
        await boundary.RecordEvidenceAsync(
            new EvidenceObservation(fixture.AttemptId, fixture.Digest('e'), fixture.Digest('f'), fixture.Now),
            CancellationToken.None);
        var entries = Success(await journal.ReadAsync(CancellationToken.None));

        Assert.Single(claims, static claim => Success(claim).Added);
        Assert.Single(claims, static claim => !Success(claim).Added);
        Assert.Equal(
            Enumerable.Range(1, entries.Count).Select(static value => (long)value),
            entries.Select(static entry => entry.Ordinal));
    }

    [Fact]
    public async Task Restart_after_stage_claim_queries_platform_status_without_repeating_stage()
    {
        var fixture = new ReleaseFixture();
        var journal = new InMemoryJournal();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        await SeedClaimAsync(journal, fixture, plan, UpgradePhase.StageClaimed);
        var staging = new RecordingStaging(initialStatus: UpgradePlatformStatus.Staged);
        var restarted = new NodeUpgradeCoordinator(journal, staging, new FixedClock(fixture.Now));

        var result = await restarted.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);

        Assert.True(Success(result).Activated);
        Assert.DoesNotContain("stage", staging.Operations);
        Assert.Equal(["health", "activate"], staging.Operations);
    }

    [Fact]
    public async Task Restart_after_health_claim_queries_platform_status_without_repeating_health_check()
    {
        var fixture = new ReleaseFixture();
        var journal = new InMemoryJournal();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        await SeedCompletionAsync(journal, fixture, plan, UpgradePhase.Staged);
        await SeedClaimAsync(journal, fixture, plan, UpgradePhase.HealthClaimed);
        var staging = new RecordingStaging(initialStatus: UpgradePlatformStatus.Healthy);
        var restarted = new NodeUpgradeCoordinator(journal, staging, new FixedClock(fixture.Now));

        var result = await restarted.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);

        Assert.True(Success(result).Activated);
        Assert.DoesNotContain("health", staging.Operations);
        Assert.Equal(["activate"], staging.Operations);
    }

    [Fact]
    public async Task Restart_after_activation_side_effect_records_terminal_state_without_repeating_activation()
    {
        var fixture = new ReleaseFixture();
        var journal = new InMemoryJournal();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        await SeedCompletionAsync(journal, fixture, plan, UpgradePhase.Staged);
        await SeedCompletionAsync(journal, fixture, plan, UpgradePhase.HealthConfirmed);
        await SeedClaimAsync(journal, fixture, plan, UpgradePhase.ActivationClaimed);
        var staging = new RecordingStaging(initialStatus: UpgradePlatformStatus.Activated);
        var restarted = new NodeUpgradeCoordinator(journal, staging, new FixedClock(fixture.Now));

        var result = await restarted.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);
        var entries = Success(await journal.ReadAsync(CancellationToken.None));

        Assert.True(Success(result).Activated);
        Assert.DoesNotContain("activate", staging.Operations);
        Assert.Contains(entries, entry => entry.Upgrade?.Phase == UpgradePhase.Activated);
    }

    [Fact]
    public async Task Coordinator_fails_closed_when_the_shared_journal_cannot_be_read_or_claimed()
    {
        var fixture = new ReleaseFixture();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var unreadable = new ReadFailingJournal(new InMemoryJournal(), failAfterReads: 0);
        var claimFailing = new InMemoryJournal(new JournalFailure("journal-unavailable", "The journal is unavailable."));

        var readFailure = await new NodeUpgradeCoordinator(
            unreadable,
            new RecordingStaging(),
            new FixedClock(fixture.Now)).ExecuteAsync(fixture.Identity, plan, CancellationToken.None);
        var claimFailure = await new NodeUpgradeCoordinator(
            claimFailing,
            new RecordingStaging(),
            new FixedClock(fixture.Now)).ExecuteAsync(fixture.Identity, plan, CancellationToken.None);

        Assert.Equal("journal-read-failed", Failure(readFailure).Code);
        Assert.Equal("journal-unavailable", Failure(claimFailure).Code);
    }

    [Fact]
    public async Task In_progress_transition_and_status_refusal_fail_without_repeating_the_effect()
    {
        var fixture = new ReleaseFixture();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var journal = new InMemoryJournal();
        var activeClaim = Transition(fixture, plan, UpgradePhase.StageClaimed, fixture.Now, fixture.Now.AddMinutes(5));
        await journal.ClaimUpgradeTransitionAsync(fixture.Identity, activeClaim, CancellationToken.None);
        var statusRefusal = new RecordingStaging(
            statusResult: Failure<UpgradePlatformStatus>("status-unavailable", "The platform state cannot be queried."));

        var inProgressStaging = new RecordingStaging();
        var inProgress = await new NodeUpgradeCoordinator(
            journal,
            inProgressStaging,
            new FixedClock(fixture.Now)).ExecuteAsync(fixture.Identity, plan, CancellationToken.None);
        var unavailable = await new NodeUpgradeCoordinator(
            new InMemoryJournal(),
            statusRefusal,
            new FixedClock(fixture.Now)).ExecuteAsync(fixture.Identity, plan, CancellationToken.None);

        Assert.True(Success(inProgress).RolledBack);
        Assert.Equal(["rollback"], inProgressStaging.Operations);
        Assert.Empty(statusRefusal.Operations);
        Assert.Equal("status-unavailable", Failure(unavailable).Code);
    }

    [Fact]
    public async Task False_stage_response_rolls_back_before_health_or_activation()
    {
        var fixture = new ReleaseFixture();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var staging = new RecordingStaging(stage: new Result<bool, UpgradeFailure>.Success(false));

        var result = await new NodeUpgradeCoordinator(
            new InMemoryJournal(),
            staging,
            new FixedClock(fixture.Now)).ExecuteAsync(fixture.Identity, plan, CancellationToken.None);

        Assert.True(Success(result).RolledBack);
        Assert.Equal("upgrade-operation-refused", Success(result).Code);
        Assert.Equal(["stage", "rollback"], staging.Operations);
    }

    [Fact]
    public async Task Encrypted_journal_claims_allocate_contiguous_ordinals_and_return_existing_claims()
    {
        var fixture = new ReleaseFixture();
        var path = Path.Combine(Path.GetTempPath(), $"armada-upgrade-claim-{Guid.NewGuid():N}.log");
        var journal = new EncryptedFileJournal(
            path,
            new AesGcmJournalProtector(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)),
            new InMemoryRollbackAnchorStore());
        var evidence = new EvidenceObservation(fixture.AttemptId, fixture.Digest('a'), fixture.Digest('b'), fixture.Now);
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var claim = Transition(fixture, plan, UpgradePhase.StageClaimed, fixture.Now, fixture.Now.AddMinutes(5));

        try
        {
            var first = await journal.AppendClaimedAsync(
                JournalEntry.EvidenceClaimIdentity(evidence),
                ordinal => JournalEntry.ForEvidence(ordinal, fixture.Identity, evidence),
                CancellationToken.None);
            var duplicate = await journal.AppendClaimedAsync(
                JournalEntry.EvidenceClaimIdentity(evidence),
                ordinal => JournalEntry.ForEvidence(ordinal, fixture.Identity, evidence),
                CancellationToken.None);
            var transition = await journal.ClaimUpgradeTransitionAsync(fixture.Identity, claim, CancellationToken.None);
            var alreadyClaimed = await journal.ClaimUpgradeTransitionAsync(
                fixture.Identity,
                claim with { OperationId = Guid.NewGuid() },
                CancellationToken.None);
            var initialFence = Fence(Success(transition).Entry.Upgrade!);
            var renewal = await journal.RenewUpgradeTransitionAsync(
                fixture.Identity,
                initialFence,
                fixture.Now.AddMinutes(1),
                fixture.Now.AddMinutes(6),
                CancellationToken.None);
            var renewedFence = Fence(Success(renewal).Entry.Upgrade!);
            var completion = Success(transition).Entry.Upgrade! with
            {
                Phase = UpgradePhase.Staged,
                ClaimExpiresAt = null,
                Fence = renewedFence.Fence
            };
            var activated = await journal.CompleteUpgradeTransitionAsync(
                fixture.Identity,
                completion,
                renewedFence,
                CancellationToken.None);
            var entries = Success(await journal.ReadAsync(CancellationToken.None));

            Assert.True(Success(first).Added);
            Assert.False(Success(duplicate).Added);
            Assert.True(Success(transition).Added);
            Assert.False(Success(alreadyClaimed).Added);
            Assert.True(Success(renewal).Added);
            Assert.True(Success(activated).Added);
            Assert.Equal([1L, 2L, 3L, 4L], entries.Select(static entry => entry.Ordinal));
        }
        finally
        {
            File.Delete(path);
            File.Delete($"{path}.anchor");
        }
    }

    [Fact]
    public async Task Expired_in_flight_claim_is_fenced_when_a_second_coordinator_takes_over()
    {
        var fixture = new ReleaseFixture();
        var journal = new InMemoryJournal();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var firstClaim = Transition(
            fixture,
            plan,
            UpgradePhase.StageClaimed,
            fixture.Now,
            fixture.Now.AddMinutes(5));
        var first = Success(await journal.ClaimUpgradeTransitionAsync(fixture.Identity, firstClaim, CancellationToken.None));
        var secondClaim = firstClaim with
        {
            OperationId = Guid.NewGuid(),
            RecordedAt = fixture.Now.AddMinutes(6),
            ClaimExpiresAt = fixture.Now.AddMinutes(11)
        };
        var second = Success(await journal.ClaimUpgradeTransitionAsync(fixture.Identity, secondClaim, CancellationToken.None));
        var firstFence = Fence(first.Entry.Upgrade!);
        var secondFence = Fence(second.Entry.Upgrade!);
        var staging = new RecordingStaging();
        var completion = first.Entry.Upgrade! with
        {
            Phase = UpgradePhase.Staged,
            ClaimExpiresAt = null
        };

        Assert.True(Success(await staging.RenewFenceAsync(plan, firstFence, CancellationToken.None)));
        Assert.True(Success(await staging.RenewFenceAsync(plan, secondFence, CancellationToken.None)));
        Assert.Equal("upgrade-fence-stale", Failure(await staging.StageAsync(plan, firstFence, CancellationToken.None)).Code);
        Assert.Equal(
            "upgrade-fence-lost",
            Failure(await journal.CompleteUpgradeTransitionAsync(
                fixture.Identity,
                completion,
                firstFence,
                CancellationToken.None)).Code);
        Assert.True(Success(await staging.StageAsync(plan, secondFence, CancellationToken.None)));
        Assert.True(Success(await journal.CompleteUpgradeTransitionAsync(
            fixture.Identity,
            completion with
            {
                OperationId = secondFence.OperationId,
                Fence = secondFence.Fence
            },
            secondFence,
            CancellationToken.None)).Added);
        Assert.Equal(["stage"], staging.Operations);
    }

    [Fact]
    public async Task Long_running_effect_renews_its_fence_before_the_claim_expires()
    {
        var fixture = new ReleaseFixture();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var staging = new DelayedStageStaging(TimeSpan.FromMilliseconds(100));
        var coordinator = new NodeUpgradeCoordinator(
            new InMemoryJournal(),
            staging,
            new FixedClock(fixture.Now),
            TimeSpan.FromMilliseconds(5));

        var result = await coordinator.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);

        Assert.True(Success(result).Activated);
        Assert.True(staging.Renewals > 3);
    }

    [Fact]
    public async Task Failed_rollback_blocks_forward_reconciliation_until_recovery_retries_it()
    {
        var fixture = new ReleaseFixture();
        var journal = new InMemoryJournal();
        var plan = Success(UpgradePlanning.Plan(fixture.State(), Verified(fixture.Release, fixture.Signer)));
        var failing = new RecordingStaging(
            health: Failure<bool>("health-failed", "Health failed."),
            rollback: Failure<bool>("rollback-failed", "Rollback transport failed."));
        var first = new NodeUpgradeCoordinator(journal, failing, new FixedClock(fixture.Now));

        var failed = await first.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);
        var recovery = new RecordingStaging(initialStatus: UpgradePlatformStatus.Staged);
        var restarted = new NodeUpgradeCoordinator(
            journal,
            recovery,
            new FixedClock(fixture.Now.AddMinutes(6)));
        var recovered = await restarted.ExecuteAsync(fixture.Identity, plan, CancellationToken.None);
        var entries = Success(await journal.ReadAsync(CancellationToken.None));

        Assert.Equal("rollback-failed", Failure(failed).Code);
        Assert.True(Success(recovered).RolledBack);
        Assert.Equal(["rollback"], recovery.Operations);
        Assert.DoesNotContain("health", recovery.Operations);
        Assert.DoesNotContain("activate", recovery.Operations);
        Assert.Equal(UpgradePhase.RolledBack, entries.Last().Upgrade!.Phase);
    }

    private static T Success<T, TFailure>(Result<T, TFailure> result) =>
        result switch
        {
            Result<T, TFailure>.Success success => success.Value,
            Result<T, TFailure>.Failure { Error: UpgradeFailure failure } =>
                throw new Xunit.Sdk.XunitException($"{failure.Code}: {failure.Message}"),
            _ => Assert.IsType<Result<T, TFailure>.Success>(result).Value
        };

    private static TFailure Failure<T, TFailure>(Result<T, TFailure> result) =>
        Assert.IsType<Result<T, TFailure>.Failure>(result).Error;

    private static VerifiedRelease Verified(SignedRelease release, IReleaseManifestVerifier verifier) =>
        Success(ReleaseVerification.Verify(release, verifier));

    private static UpgradeJournalEvent Transition(
        ReleaseFixture fixture,
        UpgradePlan plan,
        UpgradePhase phase,
        DateTimeOffset recordedAt,
        DateTimeOffset? expiresAt) =>
        new(
            plan.IdempotencyKey,
            plan.Release.Value.Manifest.ReleaseId,
            plan.Release.Value.ManifestDigest,
            phase,
            recordedAt,
            "test-transition",
            "Deterministic test transition.",
            Guid.NewGuid(),
            expiresAt,
            0);

    private static UpgradeOperationFence Fence(UpgradeJournalEvent value) =>
        new(
            value.IdempotencyKey,
            value.ReleaseId,
            value.ManifestDigest,
            value.Phase,
            value.OperationId,
            value.Fence,
            value.ClaimExpiresAt!.Value);

    private static async Task SeedClaimAsync(
        INodeJournal journal,
        ReleaseFixture fixture,
        UpgradePlan plan,
        UpgradePhase phase)
    {
        var claim = Transition(
            fixture,
            plan,
            phase,
            fixture.Now.AddMinutes(-10),
            fixture.Now.AddMinutes(-1));
        Assert.True(Success(await journal.ClaimUpgradeTransitionAsync(fixture.Identity, claim, CancellationToken.None)).Added);
    }

    private static async Task SeedCompletionAsync(
        INodeJournal journal,
        ReleaseFixture fixture,
        UpgradePlan plan,
        UpgradePhase phase)
    {
        var completion = Transition(fixture, plan, phase, fixture.Now.AddMinutes(-10), null) with
        {
            OperationId = Guid.Empty
        };
        Assert.True(Success(await journal.AppendClaimedAsync(
            JournalEntry.UpgradeClaimIdentity(completion),
            ordinal => JournalEntry.ForUpgrade(ordinal, fixture.Identity, completion),
            CancellationToken.None)).Added);
    }

    private sealed class ReleaseFixture
    {
        private static readonly byte[] Key = [1, 3, 3, 7];

        public DateTimeOffset Now { get; } = DateTimeOffset.Parse("2026-08-23T00:00:00Z");
        public NodeDeviceIdentity Identity { get; } = new(ResourceId.New(), 3);
        public ResourceId AttemptId { get; } = ResourceId.New();
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

        public NodeAgentBoundary Boundary(INodeJournal journal) =>
            new(
                Identity,
                new LocalIsolationCapabilities(ImmutableHashSet.Create(IsolationProfile.IsolatedContainer)),
                journal,
                new DeterministicVerifier(AuthorityVerification.Verified),
                new FixedClock(Now));

        public OutboundEnvelope<NodeCommand> StartEnvelope(long sequence) =>
            new(
                NodeAgentProtocol.Version,
                Identity.NodeId,
                Identity.IdentityEpoch,
                1,
                sequence,
                Guid.NewGuid(),
                Guid.NewGuid(),
                $"upgrade-journal-{sequence}",
                Now,
                new StartAttemptCommand(
                    NodeAgentProtocol.StartAttemptSchema,
                    Identity.NodeId,
                    ResourceId.New(),
                    ResourceId.New(),
                    AttemptId,
                    Now.AddMinutes(10),
                    ResourceId.New(),
                    ResourceId.New(),
                    IsolationProfile.IsolatedContainer,
                    Digest("bundle"u8),
                    Digest("policy"u8),
                    Digest("release"u8),
                    Digest("grant"u8)));

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

        public Sha256Digest Digest(char value) =>
            Digest(System.Text.Encoding.UTF8.GetBytes(new string(value, 3)));

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
        Result<bool, UpgradeFailure>? rollback = null,
        UpgradePlatformStatus initialStatus = UpgradePlatformStatus.NotStaged,
        Result<UpgradePlatformStatus, UpgradeFailure>? statusResult = null,
        bool stageLeavesStagedOnFailure = false) : IUpgradeStaging
    {
        private UpgradePlatformStatus status = initialStatus;
        private readonly Result<UpgradePlatformStatus, UpgradeFailure>? statusResult = statusResult;
        private long currentFence;
        private Guid currentOperationId;
        public List<string> Operations { get; } = [];

        public Task<Result<UpgradePlatformStatus, UpgradeFailure>> GetStatusAsync(
            UpgradePlan plan,
            CancellationToken cancellationToken) =>
            Task.FromResult(statusResult ?? Success<UpgradePlatformStatus, UpgradeFailure>(status));

        public Task<Result<bool, UpgradeFailure>> RenewFenceAsync(
            UpgradePlan plan,
            UpgradeOperationFence fence,
            CancellationToken cancellationToken)
        {
            if (fence.Fence <= currentFence)
            {
                return Task.FromResult(Failure<bool>("upgrade-fence-stale", "The staging adapter rejected a stale fencing token."));
            }
            currentFence = fence.Fence;
            currentOperationId = fence.OperationId;
            return Task.FromResult(Success<bool, UpgradeFailure>(true));
        }

        public Task<Result<bool, UpgradeFailure>> StageAsync(
            UpgradePlan plan,
            UpgradeOperationFence fence,
            CancellationToken cancellationToken)
        {
            if (fence.OperationId != currentOperationId)
            {
                return Task.FromResult(Failure<bool>("upgrade-fence-stale", "The staging adapter rejected a stale fencing token."));
            }
            Operations.Add("stage");
            var result = stage ?? Success<bool, UpgradeFailure>(true);
            if (result is Result<bool, UpgradeFailure>.Success { Value: true } ||
                stageLeavesStagedOnFailure)
            {
                status = UpgradePlatformStatus.Staged;
            }
            return Task.FromResult(result);
        }

        public Task<Result<bool, UpgradeFailure>> ConfirmHealthAsync(
            UpgradePlan plan,
            UpgradeOperationFence fence,
            CancellationToken cancellationToken)
        {
            if (fence.OperationId != currentOperationId)
            {
                return Task.FromResult(Failure<bool>("upgrade-fence-stale", "The staging adapter rejected a stale fencing token."));
            }
            Operations.Add("health");
            var result = health ?? Success<bool, UpgradeFailure>(true);
            if (result is Result<bool, UpgradeFailure>.Success { Value: true })
            {
                status = UpgradePlatformStatus.Healthy;
            }
            return Task.FromResult(result);
        }

        public Task<Result<bool, UpgradeFailure>> ActivateAsync(
            UpgradePlan plan,
            UpgradeOperationFence fence,
            CancellationToken cancellationToken)
        {
            if (fence.OperationId != currentOperationId)
            {
                return Task.FromResult(Failure<bool>("upgrade-fence-stale", "The staging adapter rejected a stale fencing token."));
            }
            Operations.Add("activate");
            var result = activation ?? Success<bool, UpgradeFailure>(true);
            if (result is Result<bool, UpgradeFailure>.Success { Value: true })
            {
                status = UpgradePlatformStatus.Activated;
            }
            return Task.FromResult(result);
        }

        public Task<Result<bool, UpgradeFailure>> RollbackAsync(
            UpgradePlan plan,
            UpgradeOperationFence fence,
            CancellationToken cancellationToken)
        {
            if (fence.OperationId != currentOperationId)
            {
                return Task.FromResult(Failure<bool>("upgrade-fence-stale", "The staging adapter rejected a stale fencing token."));
            }
            Operations.Add("rollback");
            var result = rollback ?? Success<bool, UpgradeFailure>(true);
            if (result is Result<bool, UpgradeFailure>.Success { Value: true })
            {
                status = UpgradePlatformStatus.RolledBack;
            }
            return Task.FromResult(result);
        }

        private static Result<T, TFailure> Success<T, TFailure>(T value) =>
            new Result<T, TFailure>.Success(value);
    }

    private static Result<T, UpgradeFailure> Failure<T>(string code, string message) =>
        new Result<T, UpgradeFailure>.Failure(new(code, message));

    private sealed class ReadFailingJournal(INodeJournal inner, int failAfterReads) : INodeJournal
    {
        private int reads;

        public Task<Result<JournalEntry, JournalFailure>> AppendAsync(
            JournalEntry entry,
            CancellationToken cancellationToken) =>
            inner.AppendAsync(entry, cancellationToken);

        public Task<Result<JournalAppendClaim, JournalFailure>> AppendClaimedAsync(
            string claimIdentity,
            Func<long, JournalEntry> entryFactory,
            CancellationToken cancellationToken) =>
            inner.AppendClaimedAsync(claimIdentity, entryFactory, cancellationToken);

        public Task<Result<JournalAppendClaim, JournalFailure>> ClaimUpgradeTransitionAsync(
            NodeDeviceIdentity identity,
            UpgradeJournalEvent claim,
            CancellationToken cancellationToken) =>
            inner.ClaimUpgradeTransitionAsync(identity, claim, cancellationToken);

        public Task<Result<JournalAppendClaim, JournalFailure>> RenewUpgradeTransitionAsync(
            NodeDeviceIdentity identity,
            UpgradeOperationFence fence,
            DateTimeOffset renewedAt,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken) =>
            inner.RenewUpgradeTransitionAsync(identity, fence, renewedAt, expiresAt, cancellationToken);

        public Task<Result<JournalAppendClaim, JournalFailure>> CompleteUpgradeTransitionAsync(
            NodeDeviceIdentity identity,
            UpgradeJournalEvent completion,
            UpgradeOperationFence fence,
            CancellationToken cancellationToken) =>
            inner.CompleteUpgradeTransitionAsync(identity, completion, fence, cancellationToken);

        public Task<Result<IReadOnlyList<JournalEntry>, JournalFailure>> ReadAsync(CancellationToken cancellationToken) =>
            reads++ >= failAfterReads
                ? Task.FromResult<Result<IReadOnlyList<JournalEntry>, JournalFailure>>(
                    new Result<IReadOnlyList<JournalEntry>, JournalFailure>.Failure(
                        new("journal-read-failed", "The deterministic journal read failed.")))
                : inner.ReadAsync(cancellationToken);
    }

    private sealed class DelayedStageStaging(TimeSpan stageDelay) : IUpgradeStaging
    {
        private readonly RecordingStaging inner = new();

        public int Renewals { get; private set; }

        public Task<Result<UpgradePlatformStatus, UpgradeFailure>> GetStatusAsync(
            UpgradePlan plan,
            CancellationToken cancellationToken) =>
            inner.GetStatusAsync(plan, cancellationToken);

        public Task<Result<bool, UpgradeFailure>> RenewFenceAsync(
            UpgradePlan plan,
            UpgradeOperationFence fence,
            CancellationToken cancellationToken)
        {
            Renewals++;
            return inner.RenewFenceAsync(plan, fence, cancellationToken);
        }

        public async Task<Result<bool, UpgradeFailure>> StageAsync(
            UpgradePlan plan,
            UpgradeOperationFence fence,
            CancellationToken cancellationToken)
        {
            await Task.Delay(stageDelay, cancellationToken);
            return await inner.StageAsync(plan, fence, cancellationToken);
        }

        public Task<Result<bool, UpgradeFailure>> ConfirmHealthAsync(
            UpgradePlan plan,
            UpgradeOperationFence fence,
            CancellationToken cancellationToken) =>
            inner.ConfirmHealthAsync(plan, fence, cancellationToken);

        public Task<Result<bool, UpgradeFailure>> ActivateAsync(
            UpgradePlan plan,
            UpgradeOperationFence fence,
            CancellationToken cancellationToken) =>
            inner.ActivateAsync(plan, fence, cancellationToken);

        public Task<Result<bool, UpgradeFailure>> RollbackAsync(
            UpgradePlan plan,
            UpgradeOperationFence fence,
            CancellationToken cancellationToken) =>
            inner.RollbackAsync(plan, fence, cancellationToken);
    }

    private sealed class DeterministicVerifier(AuthorityVerification result) : IAuthorityVerifier
    {
        public Task<AuthorityVerification> VerifyAsync(
            OutboundEnvelope<NodeCommand> envelope,
            CancellationToken cancellationToken) =>
            Task.FromResult(result);
    }
}
