using System.Collections.Immutable;
using System.Text.Json;
using Armada.Contracts;

namespace Armada.Application;

public sealed record GitHubProjectionTarget(
    RepositoryName Repository,
    int IssueNumber,
    string SummaryName);

public sealed record GitHubProjection(
    Guid SourceEventId,
    string IdempotencyKey,
    GitHubProjectionTarget Target,
    string Title,
    string Body,
    Sha256Digest ContentDigest);

public sealed record GitHubProjectionResult(string ExternalReference);

public sealed record GitHubProjectionReceipt(
    Guid SourceEventId,
    GitHubProjectionTarget Target,
    string IdempotencyKey,
    Sha256Digest ContentDigest,
    string ExternalReference,
    DateTimeOffset RecordedAt);

public sealed record CommittedOutboxEvent(
    LedgerEvent LedgerEvent,
    OutboxMessage OutboxMessage,
    PersistedResource Resource);

public interface ICommittedOutboxEventReader
{
    Task<IReadOnlyList<CommittedOutboxEvent>> ReadAsync(
        int maximumCount,
        CancellationToken cancellationToken);
}

public interface IGitHubProjectionPort
{
    Task<GitHubProjectionResult> UpsertAsync(
        GitHubProjection projection,
        CancellationToken cancellationToken);
}

public interface IGitHubProjectionReceiptStore
{
    Task<GitHubProjectionReceipt?> FindAsync(
        Guid sourceEventId,
        GitHubProjectionTarget target,
        CancellationToken cancellationToken);

    Task<GitHubProjectionReceipt> RecordAsync(
        GitHubProjectionReceipt receipt,
        CancellationToken cancellationToken);
}

public static class GitHubProjectionMapping
{
    public static Result<GitHubProjection, GitHubProjectionFailure> Create(
        CommittedOutboxEvent source,
        GitHubProjectionTarget target)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(target);

        if (target.IssueNumber <= 0 || string.IsNullOrWhiteSpace(target.SummaryName))
        {
            return Failure("invalid-projection-target", "A projection target requires a positive issue number and summary name.");
        }

        if (source.LedgerEvent.Type != source.OutboxMessage.Type ||
            source.LedgerEvent.IdempotencyKey != source.OutboxMessage.IdempotencyKey)
        {
            return Failure("outbox-ledger-mismatch", "The outbox message must bind exactly to its immutable ledger event.");
        }

        var title = $"Armada {target.SummaryName}: {source.Resource.Kind}/{source.Resource.Name}";
        var body = string.Join(
            Environment.NewLine,
            [
                "This is a non-authoritative Armada projection.",
                $"Event: `{source.LedgerEvent.Type}`",
                $"Resource: `{source.Resource.Kind}/{source.Resource.Id}`",
                $"Generation: `{source.Resource.Generation}`",
                $"Event ID: `{source.LedgerEvent.Id:D}`",
                $"Occurred at: `{source.LedgerEvent.OccurredAt:O}`"
            ]);
        var contentDigest = ProjectionDigest.Create(title, body);

        return new Result<GitHubProjection, GitHubProjectionFailure>.Success(
            new(
                source.LedgerEvent.Id,
                $"{source.OutboxMessage.IdempotencyKey}:github:{target.Repository}:{target.IssueNumber}",
                target,
                title,
                body,
                contentDigest));
    }

    private static Result<GitHubProjection, GitHubProjectionFailure> Failure(string code, string message) =>
        new Result<GitHubProjection, GitHubProjectionFailure>.Failure(new(code, message));
}

public sealed record GitHubProjectionFailure(string Code, string Message);

public sealed class GitHubProjectionService(
    IGitHubProjectionPort projectionPort,
    IGitHubProjectionReceiptStore receiptStore)
{
    public async Task<Result<GitHubProjectionReceipt, GitHubProjectionFailure>> ProjectAsync(
        CommittedOutboxEvent source,
        GitHubProjectionTarget target,
        DateTimeOffset recordedAt,
        CancellationToken cancellationToken)
    {
        var mapped = GitHubProjectionMapping.Create(source, target);
        if (mapped is Result<GitHubProjection, GitHubProjectionFailure>.Failure failure)
        {
            return new Result<GitHubProjectionReceipt, GitHubProjectionFailure>.Failure(failure.Error);
        }

        var projection = ((Result<GitHubProjection, GitHubProjectionFailure>.Success)mapped).Value;
        var existing = await receiptStore.FindAsync(source.LedgerEvent.Id, target, cancellationToken);
        if (existing is not null)
        {
            return existing.ContentDigest == projection.ContentDigest
                ? new Result<GitHubProjectionReceipt, GitHubProjectionFailure>.Success(existing)
                : new Result<GitHubProjectionReceipt, GitHubProjectionFailure>.Failure(
                    new("projection-receipt-content-mismatch", "A receipt already exists for a different authoritative projection."));
        }

        var projected = await projectionPort.UpsertAsync(projection, cancellationToken);
        var receipt = new GitHubProjectionReceipt(
            source.LedgerEvent.Id,
            target,
            projection.IdempotencyKey,
            projection.ContentDigest,
            projected.ExternalReference,
            recordedAt);
        return new Result<GitHubProjectionReceipt, GitHubProjectionFailure>.Success(
            await receiptStore.RecordAsync(receipt, cancellationToken));
    }
}

internal static class ProjectionDigest
{
    public static Sha256Digest Create(string title, string body)
    {
        var document = JsonSerializer.SerializeToUtf8Bytes(new ProjectionDocument(title, body));
        var hash = System.Security.Cryptography.SHA256.HashData(document);
        return Sha256Digest.Parse($"sha256:{Convert.ToHexStringLower(hash)}") switch
        {
            Result<Sha256Digest, ContractValidationError>.Success success => success.Value,
            Result<Sha256Digest, ContractValidationError>.Failure failure =>
                throw new InvalidOperationException(failure.Error.Message),
            _ => throw new InvalidOperationException("Digest creation returned an unsupported result.")
        };
    }

    private sealed record ProjectionDocument(string Title, string Body);
}
