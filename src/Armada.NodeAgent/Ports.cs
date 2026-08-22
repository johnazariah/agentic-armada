using Armada.Contracts;

namespace Armada.NodeAgent;

public sealed record AuthorityVerification(bool IsValid, string Code, string Message)
{
    public static readonly AuthorityVerification Verified = new(true, "verified", "Authority verified.");
}

public interface IAuthorityVerifier
{
    Task<AuthorityVerification> VerifyAsync(
        OutboundEnvelope<NodeCommand> envelope,
        CancellationToken cancellationToken);
}

public interface INodeJournal
{
    Task<Result<JournalEntry, JournalFailure>> AppendAsync(
        JournalEntry entry,
        CancellationToken cancellationToken);

    Task<Result<IReadOnlyList<JournalEntry>, JournalFailure>> ReadAsync(
        CancellationToken cancellationToken);
}

public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public interface INodeTransport
{
    Task SendAsync(FullReconciliationSnapshot snapshot, CancellationToken cancellationToken);
}

public interface IProcessSupervisor
{
    Task<Result<ProcessTreeObservation, ProcessSupervisorFailure>> ObserveAsync(
        AttemptRuntime attempt,
        CancellationToken cancellationToken);

    Task<Result<bool, ProcessSupervisorFailure>> RequestCancellationAsync(
        AttemptRuntime attempt,
        CancellationToken cancellationToken);
}

public sealed record JournalFailure(string Code, string Message);
public sealed record ProcessSupervisorFailure(string Code, string Message);
