using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Armada.Contracts;

namespace Armada.NodeAgent;

public enum JournalEntryType
{
    CommandDecision,
    EvidenceObservation
}

public sealed record JournalEntry(
    long Ordinal,
    JournalEntryType Type,
    ResourceId NodeId,
    long IdentityEpoch,
    long StreamEpoch,
    long Sequence,
    Guid MessageId,
    Guid CorrelationId,
    string IdempotencyKey,
    string PayloadIdentity,
    bool Accepted,
    bool AdvancesSequence,
    string Code,
    string Message,
    ResourceId? ProjectId,
    ResourceId? AttemptId,
    IsolationProfile? IsolationProfile,
    AttemptExecutionState? AttemptState,
    Sha256Digest? ManifestDigest,
    Sha256Digest? OutputDigest,
    DateTimeOffset RecordedAt)
{
    public static JournalEntry ForCommand(
        long ordinal,
        NodeDeviceIdentity identity,
        OutboundEnvelope<NodeCommand> envelope,
        CommandValidationOutcome outcome,
        DateTimeOffset recordedAt) =>
        new(
            ordinal,
            JournalEntryType.CommandDecision,
            identity.NodeId,
            identity.IdentityEpoch,
            envelope.StreamEpoch,
            envelope.Sequence,
            envelope.MessageId,
            envelope.CorrelationId,
            envelope.IdempotencyKey,
            ProtocolIdentity.Envelope(envelope.Payload, envelope.IdempotencyKey),
            outcome.Acknowledgement.Accepted,
            outcome.AdvancesSequence,
            outcome.Acknowledgement.Code,
            outcome.Acknowledgement.Message,
            envelope.Payload.ProjectId,
            envelope.Payload.AttemptId,
            outcome.IsolationProfile,
            outcome.AttemptState,
            null,
            null,
            recordedAt);

    public static JournalEntry ForEvidence(
        long ordinal,
        NodeDeviceIdentity identity,
        EvidenceObservation observation) =>
        new(
            ordinal,
            JournalEntryType.EvidenceObservation,
            identity.NodeId,
            identity.IdentityEpoch,
            0,
            0,
            Guid.Empty,
            Guid.Empty,
            $"evidence:{observation.AttemptId}:{observation.ManifestDigest}",
            observation.AttemptId.ToString(),
            true,
            false,
            "evidence-observed",
            "Evidence was observed locally.",
            null,
            observation.AttemptId,
            null,
            null,
            observation.ManifestDigest,
            observation.OutputDigest,
            observation.ObservedAt);
}

public sealed record EncryptedJournalRecord(string Nonce, string Tag, string Ciphertext);

public sealed class AesGcmJournalProtector
{
    private readonly byte[] key;

    public AesGcmJournalProtector(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
        {
            throw new ArgumentException("An AES-256 journal key must contain exactly 32 bytes.", nameof(key));
        }

        this.key = key.ToArray();
    }

    public EncryptedJournalRecord Encrypt(byte[] plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ciphertext = new byte[plaintext.Length];

        using var cipher = new AesGcm(key, tag.Length);
        cipher.Encrypt(nonce, plaintext, ciphertext, tag);
        return new(
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(tag),
            Convert.ToBase64String(ciphertext));
    }

    public Result<byte[], JournalFailure> Decrypt(EncryptedJournalRecord record)
    {
        try
        {
            var nonce = Convert.FromBase64String(record.Nonce);
            var tag = Convert.FromBase64String(record.Tag);
            var ciphertext = Convert.FromBase64String(record.Ciphertext);
            var plaintext = new byte[ciphertext.Length];

            using var cipher = new AesGcm(key, tag.Length);
            cipher.Decrypt(nonce, ciphertext, tag, plaintext);
            return new Result<byte[], JournalFailure>.Success(plaintext);
        }
        catch (FormatException)
        {
            return Failure("journal-ciphertext-invalid", "The encrypted journal record is not valid base64.");
        }
        catch (CryptographicException)
        {
            return Failure("journal-decryption-failed", "The encrypted journal record cannot be authenticated with this key.");
        }
    }

    private static Result<byte[], JournalFailure> Failure(string code, string message) =>
        new Result<byte[], JournalFailure>.Failure(new(code, message));
}

public sealed class EncryptedFileJournal : INodeJournal
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly string path;
    private readonly AesGcmJournalProtector protector;

    public EncryptedFileJournal(string path, AesGcmJournalProtector protector)
    {
        this.path = path;
        this.protector = protector;
    }

    public async Task<Result<JournalEntry, JournalFailure>> AppendAsync(
        JournalEntry entry,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(entry, SerializerOptions);
        var line = JsonSerializer.Serialize(protector.Encrypt(plaintext), SerializerOptions) + Environment.NewLine;
        await using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, useAsync: true);
        await stream.WriteAsync(Encoding.UTF8.GetBytes(line), cancellationToken);
        await stream.FlushAsync(cancellationToken);
        stream.Flush(flushToDisk: true);
        return new Result<JournalEntry, JournalFailure>.Success(entry);
    }

    public async Task<Result<IReadOnlyList<JournalEntry>, JournalFailure>> ReadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return new Result<IReadOnlyList<JournalEntry>, JournalFailure>.Success([]);
        }

        var lines = await File.ReadAllLinesAsync(path, cancellationToken);
        var entries = new List<JournalEntry>(lines.Length);
        foreach (var line in lines.Where(static line => !string.IsNullOrWhiteSpace(line)))
        {
            EncryptedJournalRecord? encrypted;
            try
            {
                encrypted = JsonSerializer.Deserialize<EncryptedJournalRecord>(line, SerializerOptions);
            }
            catch (JsonException)
            {
                return Failure("journal-ciphertext-invalid", "The encrypted journal record is not valid JSON.");
            }

            if (encrypted is null)
            {
                return Failure("journal-ciphertext-invalid", "The encrypted journal record is empty.");
            }

            if (protector.Decrypt(encrypted) is not Result<byte[], JournalFailure>.Success plaintext)
            {
                return Failure("journal-decryption-failed", "The encrypted journal record cannot be decrypted.");
            }

            try
            {
                var entry = JsonSerializer.Deserialize<JournalEntry>(plaintext.Value, SerializerOptions);
                if (entry is null)
                {
                    return Failure("journal-entry-invalid", "The decrypted journal record is empty.");
                }

                entries.Add(entry);
            }
            catch (JsonException)
            {
                return Failure("journal-entry-invalid", "The decrypted journal record is not a valid journal entry.");
            }
        }

        return new Result<IReadOnlyList<JournalEntry>, JournalFailure>.Success(entries);
    }

    private static Result<IReadOnlyList<JournalEntry>, JournalFailure> Failure(string code, string message) =>
        new Result<IReadOnlyList<JournalEntry>, JournalFailure>.Failure(new(code, message));
}

public sealed class InMemoryJournal : INodeJournal
{
    private readonly List<JournalEntry> entries = [];
    private readonly JournalFailure? appendFailure;

    public InMemoryJournal(JournalFailure? appendFailure = null)
    {
        this.appendFailure = appendFailure;
    }

    public Task<Result<JournalEntry, JournalFailure>> AppendAsync(
        JournalEntry entry,
        CancellationToken cancellationToken)
    {
        if (appendFailure is { } failure)
        {
            return Task.FromResult<Result<JournalEntry, JournalFailure>>(
                new Result<JournalEntry, JournalFailure>.Failure(failure));
        }

        entries.Add(entry);
        return Task.FromResult<Result<JournalEntry, JournalFailure>>(
            new Result<JournalEntry, JournalFailure>.Success(entry));
    }

    public Task<Result<IReadOnlyList<JournalEntry>, JournalFailure>> ReadAsync(CancellationToken cancellationToken) =>
        Task.FromResult<Result<IReadOnlyList<JournalEntry>, JournalFailure>>(
            new Result<IReadOnlyList<JournalEntry>, JournalFailure>.Success(entries.ToArray()));
}
