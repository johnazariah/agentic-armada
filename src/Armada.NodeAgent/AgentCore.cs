using System.Collections.Immutable;
using Armada.Contracts;

namespace Armada.NodeAgent;

public sealed record ProcessTransitionFailure(string Code, string Message);

public static class ProcessSupervision
{
    public static Result<AttemptRuntime, ProcessTransitionFailure> MarkStarted(AttemptRuntime attempt, DateTimeOffset now) =>
        attempt.State == AttemptExecutionState.Prepared
            ? Success(attempt with { State = AttemptExecutionState.Running, UpdatedAt = now })
            : Failure("invalid-process-transition", "Only a prepared attempt can begin supervision.");

    public static Result<AttemptRuntime, ProcessTransitionFailure> RequestCancellation(AttemptRuntime attempt, DateTimeOffset now) =>
        attempt.State switch
        {
            AttemptExecutionState.Running => Success(attempt with
            {
                State = AttemptExecutionState.CancellationRequested,
                UpdatedAt = now
            }),
            AttemptExecutionState.CancellationRequested => Success(attempt),
            _ => Failure("invalid-process-transition", "Only a running attempt can be cancelled.")
        };

    public static Result<AttemptRuntime, ProcessTransitionFailure> Observe(
        AttemptRuntime attempt,
        ProcessTreeObservation observation) =>
        observation.AttemptId != attempt.AttemptId
            ? Failure("attempt-observation-mismatch", "A process observation must bind to the observed attempt.")
            : observation.ProcessTreePresent
                ? Success(attempt with { UpdatedAt = observation.ObservedAt })
                : Success(attempt with { State = AttemptExecutionState.Terminated, UpdatedAt = observation.ObservedAt });

    private static Result<AttemptRuntime, ProcessTransitionFailure> Success(AttemptRuntime attempt) =>
        new Result<AttemptRuntime, ProcessTransitionFailure>.Success(attempt);

    private static Result<AttemptRuntime, ProcessTransitionFailure> Failure(string code, string message) =>
        new Result<AttemptRuntime, ProcessTransitionFailure>.Failure(new(code, message));
}

public sealed record ProcessedCommand(
    string PayloadIdentity,
    NodeCommandAcknowledgement Acknowledgement);

public sealed record AgentState(
    NodeDeviceIdentity Identity,
    long StreamEpoch,
    long LastInboundSequence,
    ImmutableDictionary<string, ProcessedCommand> ProcessedCommands,
    ImmutableDictionary<ResourceId, AttemptRuntime> Attempts,
    ImmutableDictionary<ResourceId, EvidenceObservation> Evidence,
    ImmutableArray<UpgradeJournalEvent> Upgrades,
    long LastJournalOrdinal)
{
    public static AgentState Empty(NodeDeviceIdentity identity) =>
        new(
            identity,
            0,
            0,
            ImmutableDictionary<string, ProcessedCommand>.Empty.WithComparers(StringComparer.Ordinal),
            ImmutableDictionary<ResourceId, AttemptRuntime>.Empty,
            ImmutableDictionary<ResourceId, EvidenceObservation>.Empty,
            ImmutableArray<UpgradeJournalEvent>.Empty,
            0);

    public static Result<AgentState, JournalFailure> Replay(
        NodeDeviceIdentity identity,
        IEnumerable<JournalEntry> entries)
    {
        var state = Empty(identity);
        foreach (var entry in entries.OrderBy(static entry => entry.Ordinal))
        {
            if (entry.Ordinal != state.LastJournalOrdinal + 1)
            {
                return new Result<AgentState, JournalFailure>.Failure(
                    new("journal-ordinal-invalid", "Journal entry ordinals must be unique and contiguous from one."));
            }

            if (entry.NodeId != identity.NodeId || entry.IdentityEpoch != identity.IdentityEpoch)
            {
                return new Result<AgentState, JournalFailure>.Failure(
                    new("journal-identity-mismatch", "The journal belongs to a different node identity epoch."));
            }

            if (entry.Accepted &&
                entry.AttemptState == AttemptExecutionState.Prepared &&
                entry.AttemptId is { } attemptId &&
                state.Attempts.ContainsKey(attemptId))
            {
                return new Result<AgentState, JournalFailure>.Failure(
                    new("attempt-binding-conflict", "A journal cannot bind an existing attempt to a second start command."));
            }

            if (entry.Accepted &&
                entry.AttemptState == AttemptExecutionState.CancellationRequested &&
                (entry.AttemptId is not { } cancellationAttempt || !state.Attempts.ContainsKey(cancellationAttempt)))
            {
                return new Result<AgentState, JournalFailure>.Failure(
                    new("journal-attempt-binding-invalid", "A cancellation journal entry must bind to an existing attempt."));
            }

            if (entry.Type == JournalEntryType.AttemptStarted &&
                (entry.AttemptId is not { } startedAttempt ||
                 !state.Attempts.TryGetValue(startedAttempt, out var existingAttempt) ||
                 existingAttempt.State != AttemptExecutionState.Prepared ||
                 entry.CapabilityGrantDigest != existingAttempt.CapabilityGrantDigest ||
                 entry.AuthorityExpiresAt != existingAttempt.AuthorityExpiresAt))
            {
                return new Result<AgentState, JournalFailure>.Failure(
                    new("journal-attempt-transition-invalid", "A durable process start must transition the matching prepared attempt."));
            }

            state = Apply(state, entry);
        }

        return new Result<AgentState, JournalFailure>.Success(state);
    }

    public static AgentState Apply(AgentState state, JournalEntry entry)
    {
        var nextState = (entry.AdvancesSequence
            ? entry.StreamEpoch > state.StreamEpoch
                ? state with { StreamEpoch = entry.StreamEpoch, LastInboundSequence = entry.Sequence }
                : entry.StreamEpoch == state.StreamEpoch
                    ? state with { LastInboundSequence = Math.Max(state.LastInboundSequence, entry.Sequence) }
                    : state
            : state) with { LastJournalOrdinal = Math.Max(state.LastJournalOrdinal, entry.Ordinal) };

        if (entry.Type == JournalEntryType.CommandDecision)
        {
            var acknowledgement = new NodeCommandAcknowledgement(
                entry.MessageId,
                entry.CorrelationId,
                entry.IdempotencyKey,
                entry.Accepted,
                false,
                entry.Code,
                entry.Message);
            if (entry.AdvancesSequence)
            {
                nextState = nextState with
                {
                    ProcessedCommands = nextState.ProcessedCommands.SetItem(
                        entry.IdempotencyKey,
                        new(entry.PayloadIdentity, acknowledgement))
                };
            }

            if (entry.Accepted && entry.AttemptId is { } attemptId && entry.ProjectId is { } projectId)
            {
                nextState = entry.AttemptState switch
                {
                    AttemptExecutionState.CancellationRequested when nextState.Attempts.TryGetValue(attemptId, out var existing) =>
                        nextState with
                        {
                            Attempts = nextState.Attempts.SetItem(
                                attemptId,
                                existing with
                                {
                                    State = AttemptExecutionState.CancellationRequested,
                                    UpdatedAt = entry.RecordedAt
                                })
                        },
                    { } attemptState when entry.IsolationProfile is { } isolation &&
                                           entry.WorkloadId is { } workloadId &&
                                           entry.AdmissionDecisionReference is { } admissionDecisionReference &&
                                           entry.LeaseReference is { } leaseReference &&
                                           entry.BundleDigest is { } bundleDigest &&
                                           entry.PolicyDigest is { } policyDigest &&
                                           entry.ReleaseDigest is { } releaseDigest &&
                                           entry.CapabilityGrantDigest is { } capabilityGrantDigest &&
                                           entry.AuthorityExpiresAt is { } authorityExpiresAt =>
                        nextState with
                        {
                            Attempts = nextState.Attempts.SetItem(
                                attemptId,
                                new(
                                    projectId,
                                    workloadId,
                                    attemptId,
                                    admissionDecisionReference,
                                    leaseReference,
                                    isolation,
                                    bundleDigest,
                                    policyDigest,
                                    releaseDigest,
                                    capabilityGrantDigest,
                                    authorityExpiresAt,
                                    attemptState,
                                    entry.RecordedAt))
                        },
                    _ => nextState
                };
            }
        }
        else if (entry.Type == JournalEntryType.AttemptStarted &&
                 entry.AttemptId is { } startedAttempt &&
                 nextState.Attempts.TryGetValue(startedAttempt, out var existingAttempt))
        {
            nextState = nextState with
            {
                Attempts = nextState.Attempts.SetItem(
                    startedAttempt,
                    existingAttempt with
                    {
                        State = AttemptExecutionState.Running,
                        UpdatedAt = entry.RecordedAt
                    })
            };
        }
        else if (entry.Type == JournalEntryType.EvidenceObservation &&
                 entry.AttemptId is { } evidenceAttemptId &&
                 entry.ManifestDigest is { } manifestDigest &&
                 entry.OutputDigest is { } outputDigest)
        {
            nextState = nextState with
            {
                Evidence = nextState.Evidence.SetItem(
                    evidenceAttemptId,
                    new(evidenceAttemptId, manifestDigest, outputDigest, entry.RecordedAt))
            };
        }
        else if (entry.Type == JournalEntryType.ReleaseUpgrade && entry.Upgrade is { } upgrade)
        {
            nextState = nextState with { Upgrades = nextState.Upgrades.Add(upgrade) };
        }

        return nextState;
    }
}

public sealed record CommandValidationOutcome(
    NodeCommandAcknowledgement Acknowledgement,
    AttemptExecutionState? AttemptState,
    IsolationProfile? IsolationProfile,
    bool AdvancesSequence);

public static class CommandValidation
{
    public static CommandValidationOutcome Validate(
        AgentState state,
        OutboundEnvelope<NodeCommand> envelope,
        AuthorityVerification verification,
        LocalIsolationCapabilities capabilities,
        DateTimeOffset now)
    {
        if (envelope.Payload is null)
        {
            return Reject(envelope, "invalid-command-payload", "A node command payload is required.");
        }

        if (string.IsNullOrWhiteSpace(envelope.IdempotencyKey) ||
            envelope.MessageId == Guid.Empty ||
            envelope.CorrelationId == Guid.Empty)
        {
            return Reject(envelope, "invalid-envelope-identity", "Commands require non-empty message, correlation, and idempotency identities.");
        }

        var payloadIdentity = ProtocolIdentity.Envelope(envelope.Payload, envelope.IdempotencyKey);
        if (state.ProcessedCommands.TryGetValue(envelope.IdempotencyKey, out var processed))
        {
            return processed.PayloadIdentity == payloadIdentity
                ? new(
                    processed.Acknowledgement with
                    {
                        MessageId = envelope.MessageId,
                        CorrelationId = envelope.CorrelationId,
                        IdempotencyKey = envelope.IdempotencyKey,
                        Duplicate = true
                    },
                    null,
                    null,
                    false)
                : Reject(envelope, "idempotency-conflict", "The idempotency key was already used with different command bindings.");
        }

        if (envelope.ProtocolVersion != NodeAgentProtocol.Version)
        {
            return Reject(envelope, "unsupported-protocol-version", "The command protocol version is not supported.");
        }
        if (envelope.NodeId != state.Identity.NodeId ||
            envelope.IdentityEpoch != state.Identity.IdentityEpoch ||
            envelope.Payload.NodeReference != state.Identity.NodeId)
        {
            return Reject(envelope, "node-identity-mismatch", "The command is not bound to this node identity epoch.");
        }
        if (envelope.StreamEpoch < state.StreamEpoch ||
            (envelope.StreamEpoch == state.StreamEpoch && envelope.Sequence <= state.LastInboundSequence))
        {
            return Reject(envelope, "stale-or-replayed-sequence", "The command stream epoch or sequence has already been observed.");
        }
        if (!verification.IsValid)
        {
            return Reject(envelope, $"authority-{verification.Code}", verification.Message);
        }
        if (envelope.Payload.ExpiresAt <= now)
        {
            return Reject(envelope, "expired-authority", "The command authority has expired.", advancesSequence: true);
        }
        if (envelope.Payload.ProjectId.Value == Guid.Empty || envelope.Payload.AttemptId.Value == Guid.Empty)
        {
            return Reject(envelope, "invalid-command-binding", "Commands require non-empty project and attempt bindings.", advancesSequence: true);
        }

        return envelope.Payload switch
        {
            StartAttemptCommand start => ValidateStart(state, envelope, capabilities, start),
            CancelAttemptCommand cancel => ValidateCancellation(state, envelope, cancel),
            _ => Reject(envelope, "unknown-command-schema", "The command schema is not recognised by this agent.", advancesSequence: true)
        };
    }

    private static CommandValidationOutcome ValidateStart(
        AgentState state,
        OutboundEnvelope<NodeCommand> envelope,
        LocalIsolationCapabilities capabilities,
        StartAttemptCommand command)
    {
        if (command.SchemaVersion != NodeAgentProtocol.StartAttemptSchema)
        {
            return Reject(envelope, "unknown-command-schema", "The start command schema is not recognised.", advancesSequence: true);
        }
        if (command.WorkloadReference.Value == Guid.Empty ||
            command.AdmissionDecisionReference.Value == Guid.Empty ||
            command.LeaseReference.Value == Guid.Empty ||
            command.BundleDigest is null ||
            command.PolicyDigest is null ||
            command.ReleaseDigest is null ||
            command.CapabilityGrantDigest is null)
        {
            return Reject(envelope, "missing-authority-binding", "Start commands require exact workload, admission, lease, bundle, policy, release, and capability bindings.", advancesSequence: true);
        }
        if (state.Attempts.ContainsKey(command.AttemptId))
        {
            return Reject(envelope, "attempt-binding-conflict", "An existing attempt can only be replayed with its original idempotency key.", advancesSequence: true);
        }
        if (!capabilities.EnforceableProfiles.Contains(command.IsolationProfile))
        {
            return Reject(envelope, "unsupported-isolation-profile", "The requested isolation profile is not enforceable on this node.", advancesSequence: true);
        }
        if (HasCrossProjectConflict(state, command.ProjectId, command.IsolationProfile))
        {
            return Reject(envelope, "cross-project-isolation-refused", "The requested attempt cannot be isolated from an active project.", advancesSequence: true);
        }

        return Accept(envelope, "accepted-start-attempt", "The start attempt command is durably accepted.", AttemptExecutionState.Prepared, command.IsolationProfile);
    }

    private static CommandValidationOutcome ValidateCancellation(
        AgentState state,
        OutboundEnvelope<NodeCommand> envelope,
        CancelAttemptCommand command)
    {
        if (command.SchemaVersion != NodeAgentProtocol.CancelAttemptSchema)
        {
            return Reject(envelope, "unknown-command-schema", "The cancellation command schema is not recognised.", advancesSequence: true);
        }
        if (command.LeaseReference.Value == Guid.Empty)
        {
            return Reject(envelope, "missing-authority-binding", "Cancellation commands require a lease binding.", advancesSequence: true);
        }
        if (string.IsNullOrWhiteSpace(command.Reason))
        {
            return Reject(envelope, "invalid-command-binding", "Cancellation commands require an exact reason.", advancesSequence: true);
        }
        if (!state.Attempts.TryGetValue(command.AttemptId, out var attempt) || attempt.ProjectId != command.ProjectId)
        {
            return Reject(envelope, "unknown-attempt-binding", "Cancellation must bind to a locally observed attempt in the same project.", advancesSequence: true);
        }
        if (command.LeaseReference != attempt.LeaseReference)
        {
            return Reject(envelope, "lease-binding-mismatch", "Cancellation must bind to the lease recorded for the attempt.", advancesSequence: true);
        }

        return Accept(
            envelope,
            "accepted-cancellation",
            "The cancellation command is durably accepted.",
            AttemptExecutionState.CancellationRequested,
            attempt.IsolationProfile);
    }

    private static bool HasCrossProjectConflict(
        AgentState state,
        ResourceId projectId,
        IsolationProfile requestedProfile) =>
        state.Attempts.Values.Any(attempt =>
            attempt.ProjectId != projectId &&
            attempt.State is not AttemptExecutionState.Terminated and not AttemptExecutionState.Failed &&
            (attempt.IsolationProfile == IsolationProfile.DedicatedNode ||
             requestedProfile == IsolationProfile.DedicatedNode));

    private static CommandValidationOutcome Accept(
        OutboundEnvelope<NodeCommand> envelope,
        string code,
        string message,
        AttemptExecutionState attemptState,
        IsolationProfile isolationProfile) =>
        new(
            new(envelope.MessageId, envelope.CorrelationId, envelope.IdempotencyKey, true, false, code, message),
            attemptState,
            isolationProfile,
            true);

    private static CommandValidationOutcome Reject(
        OutboundEnvelope<NodeCommand> envelope,
        string code,
        string message,
        bool advancesSequence = false) =>
        new(
            new(envelope.MessageId, envelope.CorrelationId, envelope.IdempotencyKey, false, false, code, message),
            null,
            null,
            advancesSequence);
}
