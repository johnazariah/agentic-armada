using System.Collections.Immutable;

namespace Armada.Contracts;

public static partial class V1Alpha1Json
{
    public static string Serialize(Node value) => SerializeWire(ToWire(value));
    public static string Serialize(NodeIdentity value) => SerializeWire(ToWire(value));
    public static string Serialize(Capability value) => SerializeWire(ToWire(value));
    public static string Serialize(AdmissionDecision value) => SerializeWire(ToWire(value));
    public static string Serialize(Attempt value) => SerializeWire(ToWire(value));
    public static string Serialize(Lease value) => SerializeWire(ToWire(value));
    public static string Serialize(AgentSession value) => SerializeWire(ToWire(value));
    public static string Serialize(EvidenceReceipt value) => SerializeWire(ToWire(value));
    public static string Serialize(Event value) => SerializeWire(ToWire(value));

    public static Result<Node, ContractValidationError> DeserializeNode(string json) => Deserialize<V1Alpha1NodeWire, Node>(json, FromWire);
    public static Result<NodeIdentity, ContractValidationError> DeserializeNodeIdentity(string json) => Deserialize<V1Alpha1NodeIdentityWire, NodeIdentity>(json, FromWire);
    public static Result<Capability, ContractValidationError> DeserializeCapability(string json) => Deserialize<V1Alpha1CapabilityWire, Capability>(json, FromWire);
    public static Result<AdmissionDecision, ContractValidationError> DeserializeAdmissionDecision(string json) => Deserialize<V1Alpha1AdmissionDecisionWire, AdmissionDecision>(json, FromWire);
    public static Result<Attempt, ContractValidationError> DeserializeAttempt(string json) => Deserialize<V1Alpha1AttemptWire, Attempt>(json, FromWire);
    public static Result<Lease, ContractValidationError> DeserializeLease(string json) => Deserialize<V1Alpha1LeaseWire, Lease>(json, FromWire);
    public static Result<AgentSession, ContractValidationError> DeserializeAgentSession(string json) => Deserialize<V1Alpha1AgentSessionWire, AgentSession>(json, FromWire);
    public static Result<EvidenceReceipt, ContractValidationError> DeserializeEvidenceReceipt(string json) => Deserialize<V1Alpha1EvidenceReceiptWire, EvidenceReceipt>(json, FromWire);
    public static Result<Event, ContractValidationError> DeserializeEvent(string json) => Deserialize<V1Alpha1EventWire, Event>(json, FromWire);

    private static string SerializeWire<T>(T value) => System.Text.Json.JsonSerializer.Serialize(value, Options);

    public static V1Alpha1NodeWire ToWire(Node value) => new(value.ApiVersion, value.Kind, ToWire(value.Metadata),
        new(value.Spec.IdentityReference.ToString(), new(value.Spec.Scheduling.MaximumConcurrency, value.Spec.Scheduling.CpuMillicores, value.Spec.Scheduling.MemoryBytes, value.Spec.Scheduling.StorageBytes), value.Spec.DesiredOperation.ToString(), value.Spec.Taints.Select(x => new V1Alpha1TaintWire(x.Key, x.Value, x.Effect.ToString())).ToArray()),
        new(value.Status.Common.ObservedGeneration, value.Status.Common.Conditions.Select(ToWire).ToArray(), value.Status.ObservedIdentityEpoch, value.Status.LastObservedAt));
    public static V1Alpha1NodeIdentityWire ToWire(NodeIdentity value) => new(value.ApiVersion, value.Kind, ToWire(value.Metadata),
        new(value.Spec.PublicKeyDigest.Value, value.Spec.RequestedAssurance.ToString(), value.Spec.IdentityEpoch, value.Spec.AttestationDigest?.Value),
        new(value.Status.Common.ObservedGeneration, value.Status.Common.Conditions.Select(ToWire).ToArray(), value.Status.CertificateSerial, value.Status.CertificateExpiresAt, value.Status.Assurance?.ToString(), value.Status.RevokedAt));
    public static V1Alpha1CapabilityWire ToWire(Capability value) => new(value.ApiVersion, value.Kind, ToWire(value.Metadata),
        new(value.Spec.NodeReference.ToString(), value.Spec.RequestedScopes.OrderBy(x => x, StringComparer.Ordinal).ToArray()),
        new(value.Status.Common.ObservedGeneration, value.Status.Common.Conditions.Select(ToWire).ToArray(), value.Status.VerifiedScopes.OrderBy(x => x, StringComparer.Ordinal).ToArray(), value.Status.InventoryDigest?.Value, value.Status.VerifiedAt));
    public static V1Alpha1AdmissionDecisionWire ToWire(AdmissionDecision value) => new(value.ApiVersion, value.Kind, ToWire(value.Metadata),
        new(value.Spec.WorkloadReference.ToString(), value.Spec.WorkloadGeneration, value.Spec.NodeReference.ToString(), value.Spec.BundleDigest.Value, value.Spec.PolicyDigest.Value, value.Spec.SourceRepository.Value, value.Spec.SourceRevision, value.Spec.ConfigDigest.Value, value.Spec.ApprovedActions.OrderBy(x => x, StringComparer.Ordinal).ToArray(), value.Spec.SessionAuthority.ToString(), value.Spec.IsolationProfile.ToString(), ToWire(value.Spec.ResourceLimits), value.Spec.CredentialGrantDigests.Select(x => x.Value).ToArray(), new(value.Spec.NetworkScope.OrderBy(x => x, StringComparer.Ordinal).ToArray()), new(value.Spec.EvidenceRequirementsDigest.Value), value.Spec.ExpiresAt),
        new(value.Status.Common.ObservedGeneration, value.Status.Common.Conditions.Select(ToWire).ToArray(), value.Status.Decision.ToString(), value.Status.DecisionDigest?.Value));
    public static V1Alpha1AttemptWire ToWire(Attempt value) => new(value.ApiVersion, value.Kind, ToWire(value.Metadata),
        new(value.Spec.WorkloadReference.ToString(), value.Spec.WorkloadGeneration, value.Spec.NodeReference.ToString(), value.Spec.AdmissionDecisionReference.ToString(), value.Spec.BundleDigest.Value, value.Spec.PolicyDigest.Value, value.Spec.CapabilityGrantDigest.Value, value.Spec.EnvironmentDigest.Value),
        new(value.Status.Common.ObservedGeneration, value.Status.Common.Conditions.Select(ToWire).ToArray(), value.Status.TerminalObservation is null ? null : LifecycleValue(value.Status.TerminalObservation.Value)));
    public static V1Alpha1LeaseWire ToWire(Lease value) => new(value.ApiVersion, value.Kind, ToWire(value.Metadata),
        new(value.Spec.AttemptReference.ToString(), value.Spec.NodeReference.ToString(), value.Spec.HolderEpoch, value.Spec.ExpiresAt),
        new(value.Status.Common.ObservedGeneration, value.Status.Common.Conditions.Select(ToWire).ToArray(), value.Status.LastHeartbeatAt, value.Status.RevokedAt));
    public static V1Alpha1AgentSessionWire ToWire(AgentSession value) => new(value.ApiVersion, value.Kind, ToWire(value.Metadata),
        new(value.Spec.AttemptReference.ToString(), value.Spec.NodeReference.ToString(), new("GitHubCopilot", value.Spec.Provider.ProfileDigest.Value), value.Spec.Role.ToString(), value.Spec.IdempotencyKey, value.Spec.ParentSessionReference?.ToString()),
        new(value.Status.Common.ObservedGeneration, value.Status.Common.Conditions.Select(ToWire).ToArray(), value.Status.Owner?.Value, value.Status.Successor?.Value, value.Status.LastObservedAt, value.Status.ArchiveComplete));
    public static V1Alpha1EvidenceReceiptWire ToWire(EvidenceReceipt value) => new(value.ApiVersion, value.Kind, ToWire(value.Metadata),
        new(value.Spec.AttemptReference.ToString(), value.Spec.ManifestDigest.Value, "GitHubRelease", value.Spec.Archive.Repository.Value, value.Spec.ReleaseId, value.Spec.AssetDigest.Value),
        new(value.Status.Common.ObservedGeneration, value.Status.Common.Conditions.Select(ToWire).ToArray(), value.Status.Verification.ToString(), value.Status.VerifiedAt));
    public static V1Alpha1EventWire ToWire(Event value) => new(value.ApiVersion, value.Kind, ToWire(value.Metadata),
        new(value.Spec.Type, value.Spec.OccurredAt, value.Spec.Actor.Value, value.Spec.CorrelationId.ToString("D"), value.Spec.CausationId?.ToString("D"), value.Spec.PayloadDigest.Value),
        new(value.Status.ObservedGeneration, value.Status.Conditions.Select(ToWire).ToArray()));

    public static Result<Node, ContractValidationError> FromWire(V1Alpha1NodeWire wire) => Map("Node", wire.ApiVersion, wire.Kind, wire.Metadata, wire.Spec, wire.Status, (m, s, t) =>
        new Node(m, new NodeSpec(Id(s.IdentityRef), Ceiling(s.Scheduling), EnumValue<DesiredNodeOperation>(s.DesiredOperation), (s.Taints ?? []).Select(Taint).ToImmutableArray()), new NodeStatus(t, OptionalPositive(wire.Status?.ObservedIdentityEpoch, "observedIdentityEpoch"), wire.Status?.LastObservedAt)));
    public static Result<NodeIdentity, ContractValidationError> FromWire(V1Alpha1NodeIdentityWire wire) => Map("NodeIdentity", wire.ApiVersion, wire.Kind, wire.Metadata, wire.Spec, wire.Status, (m, s, t) =>
        new NodeIdentity(m, new NodeIdentitySpec(Digest(s.PublicKeyDigest), EnumValue<NodeAssurance>(s.RequestedAssurance), Positive(s.IdentityEpoch, "identityEpoch"), OptionalDigest(s.AttestationDigest)), new NodeIdentityStatus(t, wire.Status?.CertificateSerial, wire.Status?.CertificateExpiresAt, OptionalEnum<NodeAssurance>(wire.Status?.Assurance), wire.Status?.RevokedAt)));
    public static Result<Capability, ContractValidationError> FromWire(V1Alpha1CapabilityWire wire) => Map("Capability", wire.ApiVersion, wire.Kind, wire.Metadata, wire.Spec, wire.Status, (m, s, t) =>
        new Capability(m, new CapabilitySpec(Id(s.NodeRef), NonEmptySet(s.RequestedScopes, "requestedScopes")), new CapabilityStatus(t, Set(wire.Status?.VerifiedScopes), OptionalDigest(wire.Status?.InventoryDigest), wire.Status?.VerifiedAt)));
    public static Result<AdmissionDecision, ContractValidationError> FromWire(V1Alpha1AdmissionDecisionWire wire) => MapScoped("AdmissionDecision", wire.ApiVersion, wire.Kind, wire.Metadata, wire.Spec, wire.Status, (m, s, t) =>
        new AdmissionDecision(m, new AdmissionDecisionSpec(Id(s.WorkloadRef), Positive(s.WorkloadGeneration, "workloadGeneration"), Id(s.NodeRef), Digest(s.BundleDigest), Digest(s.PolicyDigest), Repository(s.SourceRepository), Checked(SourceRevision(s.SourceRevision)), Digest(s.ConfigDigest), NonEmptySet(s.ApprovedActions, "approvedActions"), EnumValue<SessionAuthority>(s.SessionAuthority), EnumValue<IsolationProfile>(s.IsolationProfile), Requirements(s.ResourceLimits), (s.CredentialGrantDigests ?? []).Select(Digest).ToImmutableArray(), NonEmptySet(s.NetworkScope?.Scopes, "networkScope.scopes"), Digest(s.EvidenceRequirements?.Digest), RequiredTime(s.ExpiresAt, "expiresAt")), new AdmissionDecisionStatus(t, EnumValue<AdmissionVerdict>(wire.Status?.Decision), OptionalDigest(wire.Status?.DecisionDigest))));
    public static Result<Attempt, ContractValidationError> FromWire(V1Alpha1AttemptWire wire) => MapScoped("Attempt", wire.ApiVersion, wire.Kind, wire.Metadata, wire.Spec, wire.Status, (m, s, t) =>
        new Attempt(m, new AttemptSpec(Id(s.WorkloadRef), Positive(s.WorkloadGeneration, "workloadGeneration"), Id(s.NodeRef), Id(s.AdmissionDecisionRef), Digest(s.BundleDigest), Digest(s.PolicyDigest), Digest(s.CapabilityGrantDigest), Digest(s.EnvironmentDigest)), new AttemptStatus(t, wire.Status?.TerminalObservation is null ? null : Lifecycle(wire.Status.TerminalObservation))));
    public static Result<Lease, ContractValidationError> FromWire(V1Alpha1LeaseWire wire) => MapScoped("Lease", wire.ApiVersion, wire.Kind, wire.Metadata, wire.Spec, wire.Status, (m, s, t) =>
        new Lease(m, new LeaseSpec(Id(s.AttemptRef), Id(s.NodeRef), Positive(s.HolderEpoch, "holderEpoch"), RequiredTime(s.ExpiresAt, "expiresAt")), new LeaseStatus(t, wire.Status?.LastHeartbeatAt, wire.Status?.RevokedAt)));
    public static Result<AgentSession, ContractValidationError> FromWire(V1Alpha1AgentSessionWire wire) => MapScoped("AgentSession", wire.ApiVersion, wire.Kind, wire.Metadata, wire.Spec, wire.Status, (m, s, t) =>
        new AgentSession(m, new AgentSessionSpec(Id(s.AttemptRef), Id(s.NodeRef), Profile(s.SessionProfile), EnumValue<AgentSessionRole>(s.Role), Required(s.IdempotencyKey, "idempotencyKey"), OptionalId(s.ParentSessionRef)), new AgentSessionStatus(t, OptionalActor(wire.Status?.Owner), OptionalActor(wire.Status?.Successor), wire.Status?.LastObservedAt, wire.Status?.ArchiveComplete ?? false)));
    public static Result<EvidenceReceipt, ContractValidationError> FromWire(V1Alpha1EvidenceReceiptWire wire) => MapScoped("EvidenceReceipt", wire.ApiVersion, wire.Kind, wire.Metadata, wire.Spec, wire.Status, (m, s, t) =>
        new EvidenceReceipt(m, new EvidenceReceiptSpec(Id(s.AttemptRef), Digest(s.ManifestDigest), EvidenceArchive(s.ArchiveProvider, s.ArchiveRepository), Required(s.ReleaseId, "releaseId"), Digest(s.AssetDigest)), new EvidenceReceiptStatus(t, EnumValue<EvidenceVerification>(wire.Status?.Verification), wire.Status?.VerifiedAt)));
    public static Result<Event, ContractValidationError> FromWire(V1Alpha1EventWire wire) => Map("Event", wire.ApiVersion, wire.Kind, wire.Metadata, wire.Spec, wire.Status, (m, s, t) =>
        new Event(m, new EventSpec(Required(s.Type, "type"), RequiredTime(s.OccurredAt, "occurredAt"), new ActorId(Required(s.Actor, "actor")), GuidValue(s.CorrelationId, "correlationId"), OptionalGuid(s.CausationId, "causationId"), Digest(s.PayloadDigest)), t));

    private static V1Alpha1ResourceRequirementsWire ToWire(ResourceRequirements value) => new(value.CpuMillicores, value.GpuCount, value.MemoryBytes, value.StorageBytes);
    private static T MapValue<T, TSpec, TStatus>(string kind, string? version, string? actualKind, V1Alpha1MetadataWire? metadata, TSpec? spec, TStatus? status, Func<ResourceMetadata, TSpec, ResourceStatus, T> create)
        where TSpec : class where TStatus : class, IV1Alpha1StatusWire
    {
        Envelope(kind, version, actualKind);
        return create(RequiredMetadata(metadata), RequiredObject(spec, "spec"), CommonStatus(RequiredObject(status, "status")));
    }
    private static Result<T, ContractValidationError> Map<T, TSpec, TStatus>(string kind, string? version, string? actualKind, V1Alpha1MetadataWire? metadata, TSpec? spec, TStatus? status, Func<ResourceMetadata, TSpec, ResourceStatus, T> create) where TSpec : class where TStatus : class, IV1Alpha1StatusWire =>
        Try(() => MapValue(kind, version, actualKind, metadata, spec, status, create));
    private static Result<T, ContractValidationError> MapScoped<T, TSpec, TStatus>(string kind, string? version, string? actualKind, V1Alpha1MetadataWire? metadata, TSpec? spec, TStatus? status, Func<ResourceMetadata, TSpec, ResourceStatus, T> create) where TSpec : class where TStatus : class, IV1Alpha1StatusWire =>
        Try(() => { var resource = MapValue(kind, version, actualKind, metadata, spec, status, create); if (metadata?.ProjectId is null) Fail("project-scope-required", $"{kind} metadata requires a projectId."); return resource; });

    private static Result<T, ContractValidationError> Try<T>(Func<T> map)
    {
        try { return Success(map()); }
        catch (WireValidationException error) { return Failure<T>(error.Code, error.Message); }
    }
    private static void Envelope(string kind, string? version, string? actualKind) { if (version != ArmadaApi.V1Alpha1 || actualKind != kind) Fail("invalid-resource-envelope", $"Expected an {ArmadaApi.V1Alpha1} {kind} envelope."); }
    private static T RequiredObject<T>(T? value, string name) where T : class => value ?? throw new WireValidationException("missing-required-section", $"Required {name} is missing.");
    private static ResourceMetadata RequiredMetadata(V1Alpha1MetadataWire? value) => Checked(Metadata(RequiredObject(value, "metadata")));
    private static ResourceStatus CommonStatus(IV1Alpha1StatusWire value) => Checked(Status(value.ObservedGeneration, value.Conditions));
    private static T Checked<T>(Result<T, ContractValidationError> value) => value switch { Result<T, ContractValidationError>.Success success => success.Value, Result<T, ContractValidationError>.Failure failure => throw new WireValidationException(failure.Error.Code, failure.Error.Message), _ => throw new WireValidationException("invalid-wire", "Unsupported validation result.") };
    private static string Required(string? value, string name) => !string.IsNullOrWhiteSpace(value) ? value : throw new WireValidationException("missing-required-field", $"{name} is required.");
    private static long Positive(long value, string name) => value >= 1 ? value : throw new WireValidationException("invalid-value", $"{name} must be at least one.");
    private static long? OptionalPositive(long? value, string name) => value is null || value >= 1 ? value : throw new WireValidationException("invalid-value", $"{name} must be at least one.");
    private static DateTimeOffset RequiredTime(DateTimeOffset value, string name) => value != default ? value : throw new WireValidationException("missing-required-field", $"{name} is required.");
    private static ResourceId Id(string? value) => Guid.TryParse(value, out var id) ? new ResourceId(id) : throw new WireValidationException("invalid-resource-id", "Resource references must be UUID strings.");
    private static ResourceId? OptionalId(string? value) => value is null ? null : Id(value);
    private static Guid GuidValue(string? value, string name) => Guid.TryParse(value, out var parsed) ? parsed : throw new WireValidationException("invalid-uuid", $"{name} must be a UUID string.");
    private static Guid? OptionalGuid(string? value, string name) => value is null ? null : GuidValue(value, name);
    private static Sha256Digest Digest(string? value) => Checked(Sha256Digest.Parse(value ?? string.Empty));
    private static Sha256Digest? OptionalDigest(string? value) => value is null ? null : Digest(value);
    private static RepositoryName Repository(string? value) => Checked(RepositoryName.Parse(value!));
    private static ActorId? OptionalActor(string? value) => value is null ? null : new ActorId(Required(value, "actor"));
    private static TEnum EnumValue<TEnum>(string? value) where TEnum : struct, Enum => Enum.TryParse<TEnum>(value, false, out var parsed) && Enum.IsDefined(parsed) ? parsed : throw new WireValidationException("invalid-enum", $"Unknown {typeof(TEnum).Name} value '{value}'.");
    private static TEnum? OptionalEnum<TEnum>(string? value) where TEnum : struct, Enum => value is null ? null : EnumValue<TEnum>(value);
    private static WorkloadLifecycleState Lifecycle(string value) => Checked(ParseLifecycle(value));
    private static GitHubCopilotSessionProfile Profile(V1Alpha1SessionProfileWire? value)
    {
        if (value?.Provider != "GitHubCopilot") Fail("unsupported-provider-profile", "Session profile provider must be GitHubCopilot.");
        return new GitHubCopilotSessionProfile(Digest(value!.ProfileDigest));
    }
    private static GitHubReleaseEvidenceArchiveProfile EvidenceArchive(string? provider, string? repository)
    {
        if (provider != "GitHubRelease") Fail("unsupported-provider-profile", "Evidence archive provider must be GitHubRelease.");
        return new GitHubReleaseEvidenceArchiveProfile(Repository(repository));
    }
    private static ResourceRequirements Requirements(V1Alpha1ResourceRequirementsWire? value)
    {
        if (value is null || value.CpuMillicores < 1 || value.GpuCount < 0 || value.MemoryBytes < 1 || value.StorageBytes < 1) Fail("invalid-resource-requirements", "CPU, memory, and storage must be at least one; GPU cannot be negative.");
        return new(value!.CpuMillicores, value.GpuCount, value.MemoryBytes, value.StorageBytes);
    }
    private static NodeSchedulingCeiling Ceiling(V1Alpha1NodeSchedulingCeilingWire? value)
    {
        if (value is null || value.MaximumConcurrency < 0 || value.CpuMillicores < 0 || value.MemoryBytes < 0 || value.StorageBytes < 0) Fail("invalid-scheduling-ceiling", "Node scheduling values cannot be negative.");
        return new(value!.MaximumConcurrency, value.CpuMillicores, value.MemoryBytes, value.StorageBytes);
    }
    private static Taint Taint(V1Alpha1TaintWire? value) => value is null ? throw new WireValidationException("invalid-taint", "Taints cannot contain null.") : new Taint(Required(value.Key, "taint.key"), value.Value, EnumValue<TaintEffect>(value.Effect));
    private static ImmutableHashSet<string> Set(IEnumerable<string>? values) => (values ?? []).Select(x => Required(x, "scope")).ToImmutableHashSet(StringComparer.Ordinal);
    private static ImmutableHashSet<string> NonEmptySet(IEnumerable<string>? values, string name) { var result = Set(values); if (result.Count == 0) Fail("invalid-value", $"{name} must contain at least one value."); return result; }
    private static IEnumerable<T> List<T>(IEnumerable<T?>? values, Func<T?, T> map) where T : class => (values ?? []).Select(map);
    private static void Fail(string code, string message) => throw new WireValidationException(code, message);
    private sealed class WireValidationException(string code, string message) : Exception(message) { public string Code { get; } = code; }
}

public interface IV1Alpha1StatusWire { long ObservedGeneration { get; } IReadOnlyList<V1Alpha1ConditionWire>? Conditions { get; } }
public sealed record V1Alpha1NodeWire(string ApiVersion, string Kind, V1Alpha1MetadataWire? Metadata, V1Alpha1NodeSpecWire? Spec, V1Alpha1NodeStatusWire? Status);
public sealed record V1Alpha1NodeSpecWire(string IdentityRef, V1Alpha1NodeSchedulingCeilingWire? Scheduling, string DesiredOperation, IReadOnlyList<V1Alpha1TaintWire>? Taints);
public sealed record V1Alpha1NodeSchedulingCeilingWire(int MaximumConcurrency, int CpuMillicores, long MemoryBytes, long StorageBytes);
public sealed record V1Alpha1TaintWire(string Key, string? Value, string Effect);
public sealed record V1Alpha1NodeStatusWire(long ObservedGeneration, IReadOnlyList<V1Alpha1ConditionWire>? Conditions, long? ObservedIdentityEpoch, DateTimeOffset? LastObservedAt) : IV1Alpha1StatusWire;
public sealed record V1Alpha1NodeIdentityWire(string ApiVersion, string Kind, V1Alpha1MetadataWire? Metadata, V1Alpha1NodeIdentitySpecWire? Spec, V1Alpha1NodeIdentityStatusWire? Status);
public sealed record V1Alpha1NodeIdentitySpecWire(string PublicKeyDigest, string RequestedAssurance, long IdentityEpoch, string? AttestationDigest);
public sealed record V1Alpha1NodeIdentityStatusWire(long ObservedGeneration, IReadOnlyList<V1Alpha1ConditionWire>? Conditions, string? CertificateSerial, DateTimeOffset? CertificateExpiresAt, string? Assurance, DateTimeOffset? RevokedAt) : IV1Alpha1StatusWire;
public sealed record V1Alpha1CapabilityWire(string ApiVersion, string Kind, V1Alpha1MetadataWire? Metadata, V1Alpha1CapabilitySpecWire? Spec, V1Alpha1CapabilityStatusWire? Status);
public sealed record V1Alpha1CapabilitySpecWire(string NodeRef, IReadOnlyList<string>? RequestedScopes);
public sealed record V1Alpha1CapabilityStatusWire(long ObservedGeneration, IReadOnlyList<V1Alpha1ConditionWire>? Conditions, IReadOnlyList<string>? VerifiedScopes, string? InventoryDigest, DateTimeOffset? VerifiedAt) : IV1Alpha1StatusWire;
public sealed record V1Alpha1AdmissionDecisionWire(string ApiVersion, string Kind, V1Alpha1MetadataWire? Metadata, V1Alpha1AdmissionDecisionSpecWire? Spec, V1Alpha1AdmissionDecisionStatusWire? Status);
public sealed record V1Alpha1AdmissionDecisionSpecWire(string WorkloadRef, long WorkloadGeneration, string NodeRef, string BundleDigest, string PolicyDigest, string SourceRepository, string SourceRevision, string ConfigDigest, IReadOnlyList<string>? ApprovedActions, string SessionAuthority, string IsolationProfile, V1Alpha1ResourceRequirementsWire? ResourceLimits, IReadOnlyList<string>? CredentialGrantDigests, V1Alpha1NetworkScopeWire? NetworkScope, V1Alpha1EvidenceRequirementsWire? EvidenceRequirements, DateTimeOffset ExpiresAt);
public sealed record V1Alpha1NetworkScopeWire(IReadOnlyList<string>? Scopes);
public sealed record V1Alpha1EvidenceRequirementsWire(string Digest);
public sealed record V1Alpha1AdmissionDecisionStatusWire(long ObservedGeneration, IReadOnlyList<V1Alpha1ConditionWire>? Conditions, string Decision, string? DecisionDigest) : IV1Alpha1StatusWire;
public sealed record V1Alpha1AttemptWire(string ApiVersion, string Kind, V1Alpha1MetadataWire? Metadata, V1Alpha1AttemptSpecWire? Spec, V1Alpha1AttemptStatusWire? Status);
public sealed record V1Alpha1AttemptSpecWire(string WorkloadRef, long WorkloadGeneration, string NodeRef, string AdmissionDecisionRef, string BundleDigest, string PolicyDigest, string CapabilityGrantDigest, string EnvironmentDigest);
public sealed record V1Alpha1AttemptStatusWire(long ObservedGeneration, IReadOnlyList<V1Alpha1ConditionWire>? Conditions, string? TerminalObservation) : IV1Alpha1StatusWire;
public sealed record V1Alpha1LeaseWire(string ApiVersion, string Kind, V1Alpha1MetadataWire? Metadata, V1Alpha1LeaseSpecWire? Spec, V1Alpha1LeaseStatusWire? Status);
public sealed record V1Alpha1LeaseSpecWire(string AttemptRef, string NodeRef, long HolderEpoch, DateTimeOffset ExpiresAt);
public sealed record V1Alpha1LeaseStatusWire(long ObservedGeneration, IReadOnlyList<V1Alpha1ConditionWire>? Conditions, DateTimeOffset? LastHeartbeatAt, DateTimeOffset? RevokedAt) : IV1Alpha1StatusWire;
public sealed record V1Alpha1AgentSessionWire(string ApiVersion, string Kind, V1Alpha1MetadataWire? Metadata, V1Alpha1AgentSessionSpecWire? Spec, V1Alpha1AgentSessionStatusWire? Status);
public sealed record V1Alpha1AgentSessionSpecWire(string AttemptRef, string NodeRef, V1Alpha1SessionProfileWire? SessionProfile, string Role, string IdempotencyKey, string? ParentSessionRef);
public sealed record V1Alpha1AgentSessionStatusWire(long ObservedGeneration, IReadOnlyList<V1Alpha1ConditionWire>? Conditions, string? Owner, string? Successor, DateTimeOffset? LastObservedAt, bool ArchiveComplete) : IV1Alpha1StatusWire;
public sealed record V1Alpha1EvidenceReceiptWire(string ApiVersion, string Kind, V1Alpha1MetadataWire? Metadata, V1Alpha1EvidenceReceiptSpecWire? Spec, V1Alpha1EvidenceReceiptStatusWire? Status);
public sealed record V1Alpha1EvidenceReceiptSpecWire(string AttemptRef, string ManifestDigest, string ArchiveProvider, string ArchiveRepository, string ReleaseId, string AssetDigest);
public sealed record V1Alpha1EvidenceReceiptStatusWire(long ObservedGeneration, IReadOnlyList<V1Alpha1ConditionWire>? Conditions, string Verification, DateTimeOffset? VerifiedAt) : IV1Alpha1StatusWire;
public sealed record V1Alpha1EventWire(string ApiVersion, string Kind, V1Alpha1MetadataWire? Metadata, V1Alpha1EventSpecWire? Spec, V1Alpha1EventStatusWire? Status);
public sealed record V1Alpha1EventSpecWire(string Type, DateTimeOffset OccurredAt, string Actor, string CorrelationId, string? CausationId, string PayloadDigest);
public sealed record V1Alpha1EventStatusWire(long ObservedGeneration, IReadOnlyList<V1Alpha1ConditionWire>? Conditions) : IV1Alpha1StatusWire;
