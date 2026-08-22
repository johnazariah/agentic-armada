using System.Collections.Immutable;

namespace Armada.Contracts;

public static class ArmadaApi
{
    public const string V1Alpha1 = "armada.io/v1alpha1";
}

public interface IArmadaResource
{
    string ApiVersion { get; }
    string Kind { get; }
    ResourceMetadata Metadata { get; }
}

public enum DesiredNodeOperation
{
    Active,
    Cordoned,
    Draining,
    Revoked,
    Upgrading
}

public enum TaintEffect
{
    NoSchedule,
    PreferNoSchedule,
    NoExecute
}

public enum NodeAssurance
{
    DeviceKey,
    TpmHardwareBound,
    PlatformKeyVerified
}

public enum IsolationProfile
{
    DedicatedNode,
    IsolatedContainer,
    EphemeralVm
}

public enum SessionAuthority
{
    None,
    IssueMaster,
    IssueMasterWithChildren
}

public enum AdmissionVerdict
{
    Pending,
    Admitted,
    Rejected,
    Expired
}

public enum EvidenceVerification
{
    Pending,
    Verified,
    Rejected
}

public enum AgentSessionRole
{
    MajorDomo,
    IssueMaster,
    Child
}

public sealed record GitHubSourceProfile(RepositoryName Repository);

public sealed record GitHubCopilotSessionProfile(Sha256Digest ProfileDigest);

public sealed record GitHubCopilotSessionProvider;

public sealed record GitHubReleaseEvidenceArchiveProfile(RepositoryName Repository);

public sealed record GitHubIssue(int Number, string? NodeId = null);

public sealed record GitHubPullRequest(int Number, string? NodeId = null);

public sealed record Taint(string Key, string? Value, TaintEffect Effect);

public sealed record Toleration(string Key, string Operator, string? Value, TaintEffect Effect);

public sealed record LabelSelector(ImmutableDictionary<string, string> MatchLabels);

public sealed record ResourceRequirements(
    int CpuMillicores,
    int GpuCount,
    long MemoryBytes,
    long StorageBytes);

public sealed record SchedulingRequirements(
    LabelSelector? HostSelector,
    ImmutableArray<Toleration> Tolerations,
    LabelSelector? Affinity,
    LabelSelector? AntiAffinity,
    ResourceRequirements Resources,
    decimal? MaximumEstimatedCost,
    string? CheckpointMode);

public sealed record HeartbeatPolicy(
    int IntervalSeconds,
    int TimeoutSeconds);

public sealed record ProjectSpec(
    ImmutableHashSet<RepositoryName> GitHubRepositories,
    GitHubReleaseEvidenceArchiveProfile EvidenceArchive,
    GitHubCopilotSessionProfile SessionProfile,
    Sha256Digest PolicyBundleDigest,
    decimal? BudgetLimit);

public sealed record ProjectStatus(ResourceStatus Common, decimal? BudgetObserved);

public sealed record Project(
    ResourceMetadata Metadata,
    ProjectSpec Spec,
    ProjectStatus Status) : IArmadaResource
{
    public string ApiVersion => ArmadaApi.V1Alpha1;
    public string Kind => "Project";
}

public sealed record NodeSchedulingCeiling(
    int MaximumConcurrency,
    int CpuMillicores,
    long MemoryBytes,
    long StorageBytes);

public sealed record NodeSpec(
    ResourceId IdentityReference,
    NodeSchedulingCeiling Scheduling,
    DesiredNodeOperation DesiredOperation,
    ImmutableArray<Taint> Taints);

public sealed record NodeStatus(
    ResourceStatus Common,
    long? ObservedIdentityEpoch,
    DateTimeOffset? LastObservedAt);

public sealed record Node(
    ResourceMetadata Metadata,
    NodeSpec Spec,
    NodeStatus Status) : IArmadaResource
{
    public string ApiVersion => ArmadaApi.V1Alpha1;
    public string Kind => "Node";
}

public sealed record NodeIdentitySpec(
    Sha256Digest PublicKeyDigest,
    NodeAssurance RequestedAssurance,
    long IdentityEpoch,
    Sha256Digest? AttestationDigest);

public sealed record NodeIdentityStatus(
    ResourceStatus Common,
    string? CertificateSerial,
    DateTimeOffset? CertificateExpiresAt,
    NodeAssurance? Assurance,
    DateTimeOffset? RevokedAt);

public sealed record NodeIdentity(
    ResourceMetadata Metadata,
    NodeIdentitySpec Spec,
    NodeIdentityStatus Status) : IArmadaResource
{
    public string ApiVersion => ArmadaApi.V1Alpha1;
    public string Kind => "NodeIdentity";
}

public sealed record CapabilitySpec(
    ResourceId NodeReference,
    ImmutableHashSet<string> RequestedScopes);

public sealed record CapabilityStatus(
    ResourceStatus Common,
    ImmutableHashSet<string> VerifiedScopes,
    Sha256Digest? InventoryDigest,
    DateTimeOffset? VerifiedAt);

public sealed record Capability(
    ResourceMetadata Metadata,
    CapabilitySpec Spec,
    CapabilityStatus Status) : IArmadaResource
{
    public string ApiVersion => ArmadaApi.V1Alpha1;
    public string Kind => "Capability";
}

public sealed record WorkloadEvidenceRequirement(
    GitHubReleaseEvidenceArchiveProfile Archive,
    string RetentionClass);

public sealed record WorkloadSpec(
    Sha256Digest BundleDigest,
    Sha256Digest PolicyDigest,
    GitHubSourceProfile Source,
    string SourceRevision,
    Sha256Digest ConfigDigest,
    ImmutableHashSet<string> ActionSchemas,
    GitHubCopilotSessionProvider SessionProvider,
    SessionAuthority SessionAuthority,
    IsolationProfile IsolationProfile,
    GitHubIssue GitHubIssue,
    SchedulingRequirements Scheduling,
    WorkloadEvidenceRequirement Evidence);

public enum WorkloadLifecycleState
{
    Desired,
    Admitted,
    Assigned,
    Claimed,
    StartApproved,
    Running,
    TerminalPending,
    Completed,
    Failed,
    Cancelled,
    Expired
}

public sealed record WorkloadStatus(
    ResourceStatus Common,
    WorkloadLifecycleState Lifecycle,
    ResourceId? AttemptReference,
    ActorId? Owner,
    ActorId? Successor,
    DateTimeOffset? ExpectedNextEventAt,
    DateTimeOffset? ProgressDeadlineAt,
    HeartbeatPolicy? HeartbeatPolicy,
    ActorId? Watchdog,
    ResourceId? EvidenceReceiptReference,
    GitHubPullRequest? GitHubPullRequest);

public sealed record Workload(
    ResourceMetadata Metadata,
    WorkloadSpec Spec,
    WorkloadStatus Status) : IArmadaResource
{
    public string ApiVersion => ArmadaApi.V1Alpha1;
    public string Kind => "Workload";
}

public sealed record AdmissionDecisionSpec(
    ResourceId WorkloadReference,
    long WorkloadGeneration,
    ResourceId NodeReference,
    Sha256Digest BundleDigest,
    Sha256Digest PolicyDigest,
    RepositoryName SourceRepository,
    string SourceRevision,
    Sha256Digest ConfigDigest,
    ImmutableHashSet<string> ApprovedActions,
    SessionAuthority SessionAuthority,
    IsolationProfile IsolationProfile,
    ResourceRequirements ResourceLimits,
    ImmutableArray<Sha256Digest> CredentialGrantDigests,
    ImmutableHashSet<string> NetworkScope,
    Sha256Digest EvidenceRequirementsDigest,
    DateTimeOffset ExpiresAt);

public sealed record AdmissionDecisionStatus(
    ResourceStatus Common,
    AdmissionVerdict Decision,
    Sha256Digest? DecisionDigest);

public sealed record AdmissionDecision(
    ResourceMetadata Metadata,
    AdmissionDecisionSpec Spec,
    AdmissionDecisionStatus Status) : IArmadaResource
{
    public string ApiVersion => ArmadaApi.V1Alpha1;
    public string Kind => "AdmissionDecision";
}

public sealed record AttemptSpec(
    ResourceId WorkloadReference,
    long WorkloadGeneration,
    ResourceId NodeReference,
    ResourceId AdmissionDecisionReference,
    Sha256Digest BundleDigest,
    Sha256Digest PolicyDigest,
    Sha256Digest CapabilityGrantDigest,
    Sha256Digest EnvironmentDigest);

public sealed record AttemptStatus(ResourceStatus Common, WorkloadLifecycleState? TerminalObservation);

public sealed record Attempt(
    ResourceMetadata Metadata,
    AttemptSpec Spec,
    AttemptStatus Status) : IArmadaResource
{
    public string ApiVersion => ArmadaApi.V1Alpha1;
    public string Kind => "Attempt";
}

public sealed record LeaseSpec(
    ResourceId AttemptReference,
    ResourceId NodeReference,
    long HolderEpoch,
    DateTimeOffset ExpiresAt);

public sealed record LeaseStatus(ResourceStatus Common, DateTimeOffset? LastHeartbeatAt, DateTimeOffset? RevokedAt);

public sealed record Lease(
    ResourceMetadata Metadata,
    LeaseSpec Spec,
    LeaseStatus Status) : IArmadaResource
{
    public string ApiVersion => ArmadaApi.V1Alpha1;
    public string Kind => "Lease";
}

public sealed record AgentSessionSpec(
    ResourceId AttemptReference,
    ResourceId NodeReference,
    GitHubCopilotSessionProfile Provider,
    AgentSessionRole Role,
    string IdempotencyKey,
    ResourceId? ParentSessionReference);

public sealed record AgentSessionStatus(
    ResourceStatus Common,
    ActorId? Owner,
    ActorId? Successor,
    DateTimeOffset? LastObservedAt,
    bool ArchiveComplete);

public sealed record AgentSession(
    ResourceMetadata Metadata,
    AgentSessionSpec Spec,
    AgentSessionStatus Status) : IArmadaResource
{
    public string ApiVersion => ArmadaApi.V1Alpha1;
    public string Kind => "AgentSession";
}

public sealed record EvidenceReceiptSpec(
    ResourceId AttemptReference,
    Sha256Digest ManifestDigest,
    GitHubReleaseEvidenceArchiveProfile Archive,
    string ReleaseId,
    Sha256Digest AssetDigest);

public sealed record EvidenceReceiptStatus(
    ResourceStatus Common,
    EvidenceVerification Verification,
    DateTimeOffset? VerifiedAt);

public sealed record EvidenceReceipt(
    ResourceMetadata Metadata,
    EvidenceReceiptSpec Spec,
    EvidenceReceiptStatus Status) : IArmadaResource
{
    public string ApiVersion => ArmadaApi.V1Alpha1;
    public string Kind => "EvidenceReceipt";
}

public sealed record EventSpec(
    string Type,
    DateTimeOffset OccurredAt,
    ActorId Actor,
    Guid CorrelationId,
    Guid? CausationId,
    Sha256Digest PayloadDigest);

public sealed record Event(
    ResourceMetadata Metadata,
    EventSpec Spec,
    ResourceStatus Status) : IArmadaResource
{
    public string ApiVersion => ArmadaApi.V1Alpha1;
    public string Kind => "Event";
}
