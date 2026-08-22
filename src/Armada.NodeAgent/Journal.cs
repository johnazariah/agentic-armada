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
    ResourceId? WorkloadId,
    ResourceId? AttemptId,
    ResourceId? AdmissionDecisionReference,
    ResourceId? LeaseReference,
    IsolationProfile? IsolationProfile,
    AttemptExecutionState? AttemptState,
    DateTimeOffset? AuthorityExpiresAt,
    Sha256Digest? CapabilityGrantDigest,
    Sha256Digest? BundleDigest,
    Sha256Digest? PolicyDigest,
    Sha256Digest? ReleaseDigest,
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
            envelope.Payload is StartAttemptCommand start ? start.WorkloadReference : null,
            envelope.Payload.AttemptId,
            envelope.Payload is StartAttemptCommand startAuthority ? startAuthority.AdmissionDecisionReference : null,
            envelope.Payload switch
            {
                StartAttemptCommand startLease => startLease.LeaseReference,
                CancelAttemptCommand cancelLease => cancelLease.LeaseReference,
                _ => null
            },
            outcome.IsolationProfile,
            outcome.AttemptState,
            envelope.Payload is StartAttemptCommand startExpiry ? startExpiry.ExpiresAt : null,
            envelope.Payload is StartAttemptCommand startGrant ? startGrant.CapabilityGrantDigest : null,
            envelope.Payload is StartAttemptCommand startBundle ? startBundle.BundleDigest : null,
            envelope.Payload is StartAttemptCommand startPolicy ? startPolicy.PolicyDigest : null,
            envelope.Payload is StartAttemptCommand startRelease ? startRelease.ReleaseDigest : null,
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
            null,
            observation.AttemptId,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
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

public sealed record ChainedJournalRecord(
    EncryptedJournalRecord Encrypted,
    string PreviousHash,
    string EntryHash);

public sealed record LocalJournalTailMarker(long Ordinal, string TailHash);

public sealed class EncryptedFileJournal : INodeJournal
{
    private const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly string path;
    private readonly AesGcmJournalProtector protector;
    private readonly IRollbackAnchorStore rollbackAnchorStore;

    public EncryptedFileJournal(
        string path,
        AesGcmJournalProtector protector,
        IRollbackAnchorStore rollbackAnchorStore)
    {
        this.path = path;
        this.protector = protector;
        this.rollbackAnchorStore = rollbackAnchorStore;
    }

    public async Task<Result<JournalEntry, JournalFailure>> AppendAsync(
        JournalEntry entry,
        CancellationToken cancellationToken)
    {
        var loaded = await ReadValidatedAsync(cancellationToken);
        if (loaded is Result<JournalSnapshot, JournalFailure>.Failure failure)
        {
            return Failure<JournalEntry>(failure.Error.Code, failure.Error.Message);
        }

        var snapshot = ((Result<JournalSnapshot, JournalFailure>.Success)loaded).Value;
        if (entry.Ordinal != snapshot.Anchor.Ordinal + 1)
        {
            return Failure<JournalEntry>(
                "journal-ordinal-invalid",
                "Appended journal entries must advance the durable anchor by exactly one.");
        }

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var encrypted = protector.Encrypt(JsonSerializer.SerializeToUtf8Bytes(entry, SerializerOptions));
        var chained = new ChainedJournalRecord(
            encrypted,
            snapshot.Anchor.TailHash,
            Hash(snapshot.Anchor.TailHash, encrypted));

        try
        {
            var line = JsonSerializer.Serialize(chained, SerializerOptions) + Environment.NewLine;
            await using (var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, useAsync: true))
            {
                await stream.WriteAsync(Encoding.UTF8.GetBytes(line), cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }

            var anchorResult = await WriteAnchorAsync(
                new LocalJournalTailMarker(entry.Ordinal, chained.EntryHash),
                cancellationToken);
            if (anchorResult is Result<bool, JournalFailure>.Failure anchorFailure)
            {
                return Failure<JournalEntry>(anchorFailure.Error.Code, anchorFailure.Error.Message);
            }

            var rollbackAnchor = await rollbackAnchorStore.AdvanceAsync(
                new RollbackAnchor(entry.Ordinal, chained.EntryHash),
                cancellationToken);
            if (rollbackAnchor is Result<RollbackAnchor, JournalFailure>.Failure rollbackFailure)
            {
                return Failure<JournalEntry>(rollbackFailure.Error.Code, rollbackFailure.Error.Message);
            }
            if (((Result<RollbackAnchor, JournalFailure>.Success)rollbackAnchor).Value !=
                new RollbackAnchor(entry.Ordinal, chained.EntryHash))
            {
                return Failure<JournalEntry>(
                    "rollback-anchor-invalid",
                    "The rollback-resistant anchor store did not confirm the appended journal checkpoint.");
            }
        }
        catch (IOException exception)
        {
            return Failure<JournalEntry>("journal-write-failed", exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return Failure<JournalEntry>("journal-write-failed", exception.Message);
        }

        return new Result<JournalEntry, JournalFailure>.Success(entry);
    }

    public async Task<Result<IReadOnlyList<JournalEntry>, JournalFailure>> ReadAsync(CancellationToken cancellationToken)
    {
        var loaded = await ReadValidatedAsync(cancellationToken);
        return loaded switch
        {
            Result<JournalSnapshot, JournalFailure>.Success success =>
                new Result<IReadOnlyList<JournalEntry>, JournalFailure>.Success(success.Value.Entries),
            Result<JournalSnapshot, JournalFailure>.Failure failure =>
                Failure<IReadOnlyList<JournalEntry>>(failure.Error.Code, failure.Error.Message),
            _ => Failure<IReadOnlyList<JournalEntry>>("journal-read-failed", "The journal reader returned an unsupported result.")
        };
    }

    private async Task<Result<JournalSnapshot, JournalFailure>> ReadValidatedAsync(CancellationToken cancellationToken)
    {
        var anchorPath = AnchorPath();
        var journalExists = File.Exists(path);
        var anchorExists = File.Exists(anchorPath);
        if (!journalExists && !anchorExists)
        {
            var emptyJournalAnchor = await rollbackAnchorStore.ReadAsync(cancellationToken);
            if (emptyJournalAnchor is Result<RollbackAnchor, JournalFailure>.Failure emptyAnchorFailure)
            {
                return Failure<JournalSnapshot>(emptyAnchorFailure.Error.Code, emptyAnchorFailure.Error.Message);
            }
            if (((Result<RollbackAnchor, JournalFailure>.Success)emptyJournalAnchor).Value != RollbackAnchor.Empty)
            {
                return Failure<JournalSnapshot>(
                    "journal-rollback-detected",
                    "The rollback-resistant journal anchor proves that local journal history was removed.");
            }

            return new Result<JournalSnapshot, JournalFailure>.Success(
                new([], new LocalJournalTailMarker(0, GenesisHash)));
        }
        if (journalExists != anchorExists)
        {
            return Failure<JournalSnapshot>(
                "journal-anchor-missing",
                "The encrypted journal and its durable anchor must exist together.");
        }

        string[] lines;
        try
        {
            lines = await File.ReadAllLinesAsync(path, cancellationToken);
        }
        catch (IOException exception)
        {
            return Failure<JournalSnapshot>("journal-read-failed", exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return Failure<JournalSnapshot>("journal-read-failed", exception.Message);
        }

        var entries = new List<JournalEntry>(lines.Length);
        var previousHash = GenesisHash;
        var expectedOrdinal = 1L;
        foreach (var line in lines.Where(static line => !string.IsNullOrWhiteSpace(line)))
        {
            ChainedJournalRecord? chained;
            try
            {
                chained = JsonSerializer.Deserialize<ChainedJournalRecord>(line, SerializerOptions);
            }
            catch (JsonException)
            {
                return Failure<JournalSnapshot>("journal-ciphertext-invalid", "The encrypted journal record is not valid JSON.");
            }

            if (chained is null ||
                chained.Encrypted is null ||
                chained.PreviousHash != previousHash ||
                chained.EntryHash != Hash(chained.PreviousHash, chained.Encrypted))
            {
                return Failure<JournalSnapshot>(
                    "journal-chain-invalid",
                    "The encrypted journal hash chain does not match its durable predecessor.");
            }

            if (protector.Decrypt(chained.Encrypted) is not Result<byte[], JournalFailure>.Success plaintext)
            {
                return Failure<JournalSnapshot>("journal-decryption-failed", "The encrypted journal record cannot be decrypted.");
            }

            JournalEntry? entry;
            try
            {
                entry = JsonSerializer.Deserialize<JournalEntry>(plaintext.Value, SerializerOptions);
            }
            catch (JsonException)
            {
                return Failure<JournalSnapshot>("journal-entry-invalid", "The decrypted journal record is not a valid journal entry.");
            }

            if (entry is null)
            {
                return Failure<JournalSnapshot>("journal-entry-invalid", "The decrypted journal record is empty.");
            }
            if (entry.Ordinal != expectedOrdinal)
            {
                return Failure<JournalSnapshot>(
                    "journal-ordinal-invalid",
                    "Journal entry ordinals must be unique and contiguous from one.");
            }

            entries.Add(entry);
            previousHash = chained.EntryHash;
            expectedOrdinal++;
        }

        var anchor = await ReadAnchorAsync(cancellationToken);
        if (anchor is Result<LocalJournalTailMarker, JournalFailure>.Failure anchorFailure)
        {
            return Failure<JournalSnapshot>(anchorFailure.Error.Code, anchorFailure.Error.Message);
        }

        var anchorValue = ((Result<LocalJournalTailMarker, JournalFailure>.Success)anchor).Value;
        if (anchorValue.Ordinal != entries.Count || anchorValue.TailHash != previousHash)
        {
            return Failure<JournalSnapshot>(
                "journal-rollback-detected",
                "The durable journal anchor does not match the encrypted journal tail.");
        }

        var rollbackAnchor = await rollbackAnchorStore.ReadAsync(cancellationToken);
        if (rollbackAnchor is Result<RollbackAnchor, JournalFailure>.Failure rollbackFailure)
        {
            return Failure<JournalSnapshot>(rollbackFailure.Error.Code, rollbackFailure.Error.Message);
        }

        var rollbackAnchorValue = ((Result<RollbackAnchor, JournalFailure>.Success)rollbackAnchor).Value;
        if (rollbackAnchorValue.Ordinal != anchorValue.Ordinal ||
            rollbackAnchorValue.TailHash != anchorValue.TailHash)
        {
            return Failure<JournalSnapshot>(
                "journal-rollback-detected",
                "The rollback-resistant journal anchor does not match the local journal tail.");
        }

        return new Result<JournalSnapshot, JournalFailure>.Success(new(entries, anchorValue));
    }

    private async Task<Result<LocalJournalTailMarker, JournalFailure>> ReadAnchorAsync(CancellationToken cancellationToken)
    {
        string raw;
        try
        {
            raw = await File.ReadAllTextAsync(AnchorPath(), cancellationToken);
        }
        catch (IOException exception)
        {
            return Failure<LocalJournalTailMarker>("journal-anchor-read-failed", exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return Failure<LocalJournalTailMarker>("journal-anchor-read-failed", exception.Message);
        }

        EncryptedJournalRecord? encrypted;
        try
        {
            encrypted = JsonSerializer.Deserialize<EncryptedJournalRecord>(raw, SerializerOptions);
        }
        catch (JsonException)
        {
            return Failure<LocalJournalTailMarker>("journal-anchor-invalid", "The durable journal anchor is not valid JSON.");
        }

        if (encrypted is null || protector.Decrypt(encrypted) is not Result<byte[], JournalFailure>.Success plaintext)
        {
            return Failure<LocalJournalTailMarker>("journal-anchor-invalid", "The durable journal anchor cannot be authenticated.");
        }

        try
        {
            return JsonSerializer.Deserialize<LocalJournalTailMarker>(plaintext.Value, SerializerOptions) is { } anchor
                ? new Result<LocalJournalTailMarker, JournalFailure>.Success(anchor)
                : Failure<LocalJournalTailMarker>("journal-anchor-invalid", "The durable journal anchor is empty.");
        }
        catch (JsonException)
        {
            return Failure<LocalJournalTailMarker>("journal-anchor-invalid", "The durable journal anchor has an invalid payload.");
        }
    }

    private async Task<Result<bool, JournalFailure>> WriteAnchorAsync(
        LocalJournalTailMarker anchor,
        CancellationToken cancellationToken)
    {
        var temporaryPath = $"{AnchorPath()}.tmp";
        var bytes = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(
                protector.Encrypt(JsonSerializer.SerializeToUtf8Bytes(anchor, SerializerOptions)),
                SerializerOptions));

        try
        {
            await using (var stream = new FileStream(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, useAsync: true))
            {
                await stream.WriteAsync(bytes, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, AnchorPath(), overwrite: true);
            return new Result<bool, JournalFailure>.Success(true);
        }
        catch (IOException exception)
        {
            return Failure<bool>("journal-anchor-write-failed", exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            return Failure<bool>("journal-anchor-write-failed", exception.Message);
        }
    }

    private string AnchorPath() => $"{path}.anchor";

    private static string Hash(string previousHash, EncryptedJournalRecord encrypted) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            ProtocolIdentity.Join(previousHash, encrypted.Nonce, encrypted.Tag, encrypted.Ciphertext)))).ToLowerInvariant();

    private static Result<T, JournalFailure> Failure<T>(string code, string message) =>
        new Result<T, JournalFailure>.Failure(new(code, message));

    private sealed record JournalSnapshot(
        IReadOnlyList<JournalEntry> Entries,
        LocalJournalTailMarker Anchor);
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

public sealed class InMemoryRollbackAnchorStore : IRollbackAnchorStore
{
    private RollbackAnchor anchor = RollbackAnchor.Empty;

    public Task<Result<RollbackAnchor, JournalFailure>> ReadAsync(CancellationToken cancellationToken) =>
        Task.FromResult<Result<RollbackAnchor, JournalFailure>>(
            new Result<RollbackAnchor, JournalFailure>.Success(anchor));

    public Task<Result<RollbackAnchor, JournalFailure>> AdvanceAsync(
        RollbackAnchor next,
        CancellationToken cancellationToken)
    {
        if (next.Ordinal != anchor.Ordinal + 1 || string.IsNullOrWhiteSpace(next.TailHash))
        {
            return Task.FromResult<Result<RollbackAnchor, JournalFailure>>(
                new Result<RollbackAnchor, JournalFailure>.Failure(
                    new("rollback-anchor-nonmonotonic", "Rollback anchors must advance by one durable journal ordinal.")));
        }

        anchor = next;
        return Task.FromResult<Result<RollbackAnchor, JournalFailure>>(
            new Result<RollbackAnchor, JournalFailure>.Success(anchor));
    }
}

public sealed class UnavailableRollbackAnchorStore : IRollbackAnchorStore
{
    public Task<Result<RollbackAnchor, JournalFailure>> ReadAsync(CancellationToken cancellationToken) =>
        Task.FromResult<Result<RollbackAnchor, JournalFailure>>(
            new Result<RollbackAnchor, JournalFailure>.Failure(
                new("rollback-anchor-unavailable", "A rollback-resistant anchor store is required before restoring the journal.")));

    public Task<Result<RollbackAnchor, JournalFailure>> AdvanceAsync(
        RollbackAnchor next,
        CancellationToken cancellationToken) =>
        Task.FromResult<Result<RollbackAnchor, JournalFailure>>(
            new Result<RollbackAnchor, JournalFailure>.Failure(
                new("rollback-anchor-unavailable", "A rollback-resistant anchor store is required before recording the journal.")));
}
