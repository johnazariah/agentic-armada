using System.Collections.Immutable;
using Armada.Contracts;

namespace Armada.Application;

public enum PfqeReferenceKind
{
    Evidence,
    Identity,
    HostBoundary
}

public sealed record PfqeImmutableReference(
    PfqeReferenceKind Kind,
    string SourceLocation,
    Sha256Digest ContentDigest);

public enum PfqeMigrationStage
{
    Inventory = 1,
    ObservationCandidates = 2,
    ObserverAgent = 3,
    ReviewedIdentity = 4,
    NonScientificCanary = 5,
    ReviewedRetirement = 6
}

public sealed record PfqeObserverCandidate(
    string ProfileName,
    ImmutableArray<PfqeImmutableReference> References,
    bool ObserverOnly,
    bool WorkloadAuthorityGranted,
    bool ReadinessImported);

public sealed record PfqeMigrationInventory(
    ImmutableArray<PfqeImmutableReference> References,
    ImmutableArray<PfqeObserverCandidate> Candidates,
    PfqeMigrationStage Stage,
    ImmutableArray<PfqeMigrationStageEvidence> StageEvidence);

public sealed record PfqeMigrationStageEvidence(
    PfqeMigrationStage Stage,
    string SourceLocation,
    Sha256Digest ContentDigest,
    bool IsNonScientificCanary);

public sealed record PfqeMigrationFailure(string Code, string Message);

public static class PfqeMigration
{
    public static Result<PfqeMigrationInventory, PfqeMigrationFailure> CreateInventory(
        IEnumerable<PfqeImmutableReference> references,
        IEnumerable<string> candidateProfiles,
        PfqeMigrationStageEvidence inventoryEvidence)
    {
        ArgumentNullException.ThrowIfNull(references);
        ArgumentNullException.ThrowIfNull(candidateProfiles);

        var immutableReferences = references.ToImmutableArray();
        if (immutableReferences.Length == 0 ||
            immutableReferences.Any(static reference =>
                string.IsNullOrWhiteSpace(reference.SourceLocation) ||
                reference.ContentDigest is null))
        {
            return Failure("invalid-reference-inventory", "Every migration reference requires a source location and immutable content digest.");
        }

        if (immutableReferences.Select(static reference => (reference.Kind, reference.SourceLocation, reference.ContentDigest))
            .Distinct()
            .Count() != immutableReferences.Length)
        {
            return Failure("duplicate-reference-inventory", "Migration references must be unique immutable identities.");
        }

        if (!IsValidStageEvidence(inventoryEvidence, PfqeMigrationStage.Inventory))
        {
            return Failure("invalid-stage-evidence", "Observer inventory requires an immutable inventory-stage evidence reference.");
        }

        var candidates = candidateProfiles
            .Select(static profile => profile?.Trim())
            .ToImmutableArray();
        if (candidates.Length == 0 ||
            candidates.Any(string.IsNullOrWhiteSpace) ||
            candidates.Distinct(StringComparer.Ordinal).Count() != candidates.Length)
        {
            return Failure("invalid-observer-candidate", "Observer candidates require unique non-empty profile names.");
        }

        var observerCandidates = candidates
            .Select(profile => new PfqeObserverCandidate(
                profile!,
                immutableReferences,
                ObserverOnly: true,
                WorkloadAuthorityGranted: false,
                ReadinessImported: false))
            .ToImmutableArray();

        return new Result<PfqeMigrationInventory, PfqeMigrationFailure>.Success(
            new(immutableReferences, observerCandidates, PfqeMigrationStage.Inventory, [inventoryEvidence]));
    }

    public static Result<PfqeMigrationInventory, PfqeMigrationFailure> Advance(
        PfqeMigrationInventory inventory,
        PfqeMigrationStage nextStage,
        PfqeMigrationStageEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(inventory);

        if ((int)nextStage != (int)inventory.Stage + 1)
        {
            return Failure("invalid-migration-stage", "Migration stages may advance only one reviewed stage at a time.");
        }

        if (!HasCompleteEvidenceChain(inventory))
        {
            return Failure("migration-evidence-chain-invalid", "Migration advancement requires an ordered immutable evidence chain from inventory through the current stage.");
        }

        if (!IsValidStageEvidence(evidence, nextStage))
        {
            return Failure("invalid-stage-evidence", "Each migration stage requires its own immutable evidence; the canary stage must be explicitly non-scientific.");
        }

        if (inventory.Candidates.Any(candidate =>
                !candidate.ObserverOnly ||
                candidate.WorkloadAuthorityGranted ||
                candidate.ReadinessImported ||
                !candidate.References.SequenceEqual(inventory.References)))
        {
            return Failure("observer-authority-violation", "PFQE migration candidates remain observer-only and cannot import readiness or workload authority.");
        }

        return new Result<PfqeMigrationInventory, PfqeMigrationFailure>.Success(
            inventory with { Stage = nextStage, StageEvidence = inventory.StageEvidence.Add(evidence) });
    }

    private static bool HasCompleteEvidenceChain(PfqeMigrationInventory inventory) =>
        Enum.IsDefined(inventory.Stage) &&
        inventory.StageEvidence.Length == (int)inventory.Stage &&
        inventory.StageEvidence.Select(static (evidence, index) => IsValidStageEvidence(
            evidence,
            (PfqeMigrationStage)(index + 1))).All(static valid => valid);

    private static bool IsValidStageEvidence(
        PfqeMigrationStageEvidence evidence,
        PfqeMigrationStage expectedStage) =>
        evidence.Stage == expectedStage &&
        string.IsNullOrWhiteSpace(evidence.SourceLocation) == false &&
        evidence.ContentDigest is not null &&
        (expectedStage == PfqeMigrationStage.NonScientificCanary
            ? evidence.IsNonScientificCanary
            : !evidence.IsNonScientificCanary);

    private static Result<PfqeMigrationInventory, PfqeMigrationFailure> Failure(string code, string message) =>
        new Result<PfqeMigrationInventory, PfqeMigrationFailure>.Failure(new(code, message));
}
