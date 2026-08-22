using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Armada.Contracts;

namespace Armada.NodeAgent;

public enum JournalEntryType
{
    CommandDecision,
    AttemptStarted,
    EvidenceObservation,
    ReleaseUpgrade
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
    DateTimeOffset RecordedAt,
    UpgradeJournalEvent? Upgrade = null)
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
            CommandClaimIdentity(envelope),
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
            EvidenceClaimIdentity(observation),
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

    public static JournalEntry ForAttemptStarted(
        long ordinal,
        NodeDeviceIdentity identity,
        AttemptRuntime attempt,
        DateTimeOffset recordedAt) =>
        new(
            ordinal,
            JournalEntryType.AttemptStarted,
            identity.NodeId,
            identity.IdentityEpoch,
            0,
            0,
            Guid.Empty,
            Guid.Empty,
            $"attempt-start:{attempt.AttemptId}",
            AttemptStartClaimIdentity(
                attempt.ProjectId.ToString(),
                attempt.WorkloadId.ToString(),
                attempt.AttemptId.ToString(),
                attempt.AdmissionDecisionReference.ToString(),
                attempt.LeaseReference.ToString(),
                attempt.BundleDigest.Value,
                attempt.PolicyDigest.Value,
                attempt.ReleaseDigest.Value,
                attempt.CapabilityGrantDigest.Value,
                attempt.AuthorityExpiresAt.ToUniversalTime().ToString("O")),
            true,
            false,
            "attempt-started",
            "The attempt entered durable running supervision.",
            attempt.ProjectId,
            attempt.WorkloadId,
            attempt.AttemptId,
            attempt.AdmissionDecisionReference,
            attempt.LeaseReference,
            attempt.IsolationProfile,
            AttemptExecutionState.Running,
            attempt.AuthorityExpiresAt,
            attempt.CapabilityGrantDigest,
            attempt.BundleDigest,
            attempt.PolicyDigest,
            attempt.ReleaseDigest,
            null,
            null,
            recordedAt);

    public static JournalEntry ForUpgrade(
        long ordinal,
        NodeDeviceIdentity identity,
        UpgradeJournalEvent upgrade) =>
        new(
            ordinal,
            JournalEntryType.ReleaseUpgrade,
            identity.NodeId,
            identity.IdentityEpoch,
            0,
            0,
            Guid.Empty,
            Guid.Empty,
            upgrade.IdempotencyKey,
            UpgradeClaimIdentity(upgrade),
            true,
            false,
            upgrade.Code,
            upgrade.Message,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            upgrade.RecordedAt,
            upgrade);

    public static string EvidenceClaimIdentity(EvidenceObservation observation) =>
        ProtocolIdentity.Join(
            "evidence",
            observation.AttemptId.ToString(),
            observation.ManifestDigest.Value,
            observation.OutputDigest.Value);

    public static string CommandClaimIdentity(OutboundEnvelope<NodeCommand> envelope) =>
        ProtocolIdentity.Join(
            "node-command",
            envelope.ProtocolVersion,
            envelope.NodeId.ToString(),
            envelope.IdentityEpoch.ToString(),
            envelope.StreamEpoch.ToString(),
            envelope.Sequence.ToString(),
            ProtocolIdentity.Envelope(envelope.Payload, envelope.IdempotencyKey));

    public static string AttemptStartClaimIdentity(
        string projectId,
        string workloadId,
        string attemptId,
        string admissionDecisionId,
        string leaseId,
        string bundleDigest,
        string policyDigest,
        string releaseDigest,
        string capabilityGrantDigest,
        string authorityExpiresAt) =>
        ProtocolIdentity.Join(
            "attempt-start",
            projectId,
            workloadId,
            attemptId,
            admissionDecisionId,
            leaseId,
            bundleDigest,
            policyDigest,
            releaseDigest,
            capabilityGrantDigest,
            authorityExpiresAt);

    public static string UpgradeClaimIdentity(UpgradeJournalEvent upgrade) =>
        ProtocolIdentity.Join(
            "release-upgrade",
            upgrade.IdempotencyKey,
            upgrade.Phase.ToString(),
            upgrade.OperationId.ToString("D"));
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
        var recordValidation = ValidateRecord(record);
        if (recordValidation is Result<bool, JournalFailure>.Failure validationFailure)
        {
            return Failure(validationFailure.Error.Code, validationFailure.Error.Message);
        }

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
        catch (ArgumentException)
        {
            return Failure("journal-ciphertext-invalid", "The encrypted journal record has invalid cryptographic parameters.");
        }
        catch (InvalidOperationException)
        {
            return Failure("journal-ciphertext-invalid", "The encrypted journal record cannot be processed.");
        }
    }

    public static Result<bool, JournalFailure> ValidateRecord(EncryptedJournalRecord? record)
    {
        if (record is null ||
            string.IsNullOrWhiteSpace(record.Nonce) ||
            string.IsNullOrWhiteSpace(record.Tag) ||
            string.IsNullOrWhiteSpace(record.Ciphertext))
        {
            return new Result<bool, JournalFailure>.Failure(
                new("journal-ciphertext-invalid", "The encrypted journal record requires nonce, tag, and ciphertext fields."));
        }

        try
        {
            var nonce = Convert.FromBase64String(record.Nonce);
            var tag = Convert.FromBase64String(record.Tag);
            var ciphertext = Convert.FromBase64String(record.Ciphertext);
            return nonce.Length == 12 && tag.Length == 16 && ciphertext.Length > 0
                ? new Result<bool, JournalFailure>.Success(true)
                : new Result<bool, JournalFailure>.Failure(
                    new("journal-ciphertext-invalid", "The encrypted journal record has invalid nonce, tag, or ciphertext lengths."));
        }
        catch (FormatException)
        {
            return new Result<bool, JournalFailure>.Failure(
                new("journal-ciphertext-invalid", "The encrypted journal record is not valid base64."));
        }
        catch (ArgumentException)
        {
            return new Result<bool, JournalFailure>.Failure(
                new("journal-ciphertext-invalid", "The encrypted journal record has invalid base64 fields."));
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
    private readonly SemaphoreSlim operationGate = new(1, 1);

    public EncryptedFileJournal(string path, AesGcmJournalProtector protector)
        : this(path, protector, new PlatformRollbackAnchorStore())
    {
    }

    internal EncryptedFileJournal(
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
        await operationGate.WaitAsync(cancellationToken);
        try
        {
            return await AppendCoreAsync(entry, cancellationToken);
        }
        finally
        {
            operationGate.Release();
        }
    }

    public async Task<Result<JournalAppendClaim, JournalFailure>> AppendClaimedAsync(
            string claimIdentity,
            Func<long, JournalEntry> entryFactory,
            CancellationToken cancellationToken)
        {
            await operationGate.WaitAsync(cancellationToken);
            try
            {
                var loaded = await ReadValidatedAsync(cancellationToken);
                if (loaded is Result<JournalSnapshot, JournalFailure>.Failure failure)
                {
                    return new Result<JournalAppendClaim, JournalFailure>.Failure(failure.Error);
                }

                var snapshot = ((Result<JournalSnapshot, JournalFailure>.Success)loaded).Value;
                var existing = snapshot.Entries.SingleOrDefault(entry => entry.PayloadIdentity == claimIdentity);
                if (existing is not null)
                {
                    return new Result<JournalAppendClaim, JournalFailure>.Success(new(existing, false));
                }

                var entry = entryFactory(snapshot.Anchor.Ordinal + 1);
                if (entry.PayloadIdentity != claimIdentity)
                {
                    return new Result<JournalAppendClaim, JournalFailure>.Failure(
                        new("journal-claim-identity-mismatch", "The claimed journal entry must retain its supplied claim identity."));
                }

                return await AppendCoreAsync(entry, cancellationToken) switch
                {
                    Result<JournalEntry, JournalFailure>.Success success =>
                        new Result<JournalAppendClaim, JournalFailure>.Success(new(success.Value, true)),
                    Result<JournalEntry, JournalFailure>.Failure appendFailure =>
                        new Result<JournalAppendClaim, JournalFailure>.Failure(appendFailure.Error),
                    _ => new Result<JournalAppendClaim, JournalFailure>.Failure(
                        new("journal-write-failed", "The journal append returned an unsupported result."))
                };
            }
            finally
            {
                operationGate.Release();
            }
        }

    public async Task<Result<JournalAppendClaim, JournalFailure>> ClaimUpgradeTransitionAsync(
            NodeDeviceIdentity identity,
            UpgradeJournalEvent claim,
            CancellationToken cancellationToken)
        {
            await operationGate.WaitAsync(cancellationToken);
            try
            {
                var loaded = await ReadValidatedAsync(cancellationToken);
                if (loaded is Result<JournalSnapshot, JournalFailure>.Failure failure)
                {
                    return new Result<JournalAppendClaim, JournalFailure>.Failure(failure.Error);
                }

                var snapshot = ((Result<JournalSnapshot, JournalFailure>.Success)loaded).Value;
                var existing = snapshot.Entries
                    .Where(entry =>
                        entry.Upgrade?.IdempotencyKey == claim.IdempotencyKey &&
                        entry.Upgrade.Phase == claim.Phase)
                    .OrderBy(static entry => entry.Ordinal)
                    .LastOrDefault();
                if (existing?.Upgrade?.ClaimExpiresAt is { } expiresAt && expiresAt > claim.RecordedAt)
                {
                    return new Result<JournalAppendClaim, JournalFailure>.Success(new(existing, false));
                }

                var entry = JournalEntry.ForUpgrade(snapshot.Anchor.Ordinal + 1, identity, claim);
                return await AppendCoreAsync(entry, cancellationToken) switch
                {
                    Result<JournalEntry, JournalFailure>.Success success =>
                        new Result<JournalAppendClaim, JournalFailure>.Success(new(success.Value, true)),
                    Result<JournalEntry, JournalFailure>.Failure appendFailure =>
                        new Result<JournalAppendClaim, JournalFailure>.Failure(appendFailure.Error),
                    _ => new Result<JournalAppendClaim, JournalFailure>.Failure(
                        new("journal-write-failed", "The journal transition claim returned an unsupported result."))
                };
            }
            finally
            {
                operationGate.Release();
            }
        }
    private async Task<Result<JournalEntry, JournalFailure>> AppendCoreAsync(
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
        await operationGate.WaitAsync(cancellationToken);
        try
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
        finally
        {
            operationGate.Release();
        }
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

            if (chained is null)
            {
                return Failure<JournalSnapshot>("journal-chain-invalid", "The encrypted journal chain record is empty.");
            }
            if (AesGcmJournalProtector.ValidateRecord(chained.Encrypted) is Result<bool, JournalFailure>.Failure recordFailure)
            {
                return Failure<JournalSnapshot>(recordFailure.Error.Code, recordFailure.Error.Message);
            }
            if (!IsHash(chained.PreviousHash) ||
                !IsHash(chained.EntryHash) ||
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
            if (entry.NodeId.Value == Guid.Empty || entry.IdentityEpoch < 0)
            {
                return Failure<JournalSnapshot>(
                    "journal-entry-invalid",
                    "Journal entries require a non-empty node identity and non-negative identity epoch.");
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

        if (protector.Decrypt(encrypted!) is not Result<byte[], JournalFailure>.Success plaintext)
        {
            return Failure<LocalJournalTailMarker>("journal-anchor-invalid", "The durable journal anchor cannot be authenticated.");
        }

        try
        {
            return JsonSerializer.Deserialize<LocalJournalTailMarker>(plaintext.Value, SerializerOptions) is { } anchor &&
                   anchor.Ordinal >= 0 &&
                   IsHash(anchor.TailHash)
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

    private static bool IsHash(string? value) =>
        value is { Length: 64 } && value.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

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
    private readonly object sync = new();

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

        lock (sync)
        {
            entries.Add(entry);
        }
        return Task.FromResult<Result<JournalEntry, JournalFailure>>(
            new Result<JournalEntry, JournalFailure>.Success(entry));
    }

    public Task<Result<JournalAppendClaim, JournalFailure>> AppendClaimedAsync(
            string claimIdentity,
            Func<long, JournalEntry> entryFactory,
            CancellationToken cancellationToken)
        {
            if (appendFailure is { } failure)
            {
                return Task.FromResult<Result<JournalAppendClaim, JournalFailure>>(
                    new Result<JournalAppendClaim, JournalFailure>.Failure(failure));
            }

            lock (sync)
            {
                var existing = entries.SingleOrDefault(entry => entry.PayloadIdentity == claimIdentity);
                if (existing is not null)
                {
                    return Task.FromResult<Result<JournalAppendClaim, JournalFailure>>(
                        new Result<JournalAppendClaim, JournalFailure>.Success(new(existing, false)));
                }

                var entry = entryFactory(entries.Count + 1L);
                return entry.PayloadIdentity != claimIdentity
                    ? Task.FromResult<Result<JournalAppendClaim, JournalFailure>>(
                        new Result<JournalAppendClaim, JournalFailure>.Failure(
                            new("journal-claim-identity-mismatch", "The claimed journal entry must retain its supplied claim identity.")))
                    : AppendClaimed(entry);
            }
        }

    public Task<Result<JournalAppendClaim, JournalFailure>> ClaimUpgradeTransitionAsync(
            NodeDeviceIdentity identity,
            UpgradeJournalEvent claim,
            CancellationToken cancellationToken)
        {
            if (appendFailure is { } failure)
            {
                return Task.FromResult<Result<JournalAppendClaim, JournalFailure>>(
                    new Result<JournalAppendClaim, JournalFailure>.Failure(failure));
            }

            lock (sync)
            {
                var existing = entries
                    .Where(entry =>
                        entry.Upgrade?.IdempotencyKey == claim.IdempotencyKey &&
                        entry.Upgrade.Phase == claim.Phase)
                    .OrderBy(static entry => entry.Ordinal)
                    .LastOrDefault();
                if (existing?.Upgrade?.ClaimExpiresAt is { } expiresAt && expiresAt > claim.RecordedAt)
                {
                    return Task.FromResult<Result<JournalAppendClaim, JournalFailure>>(
                        new Result<JournalAppendClaim, JournalFailure>.Success(new(existing, false)));
                }

                return AppendClaimed(JournalEntry.ForUpgrade(entries.Count + 1L, identity, claim));
            }
        }

    public Task<Result<IReadOnlyList<JournalEntry>, JournalFailure>> ReadAsync(CancellationToken cancellationToken)
    {
        lock (sync)
        {
            return Task.FromResult<Result<IReadOnlyList<JournalEntry>, JournalFailure>>(
                new Result<IReadOnlyList<JournalEntry>, JournalFailure>.Success(entries.ToArray()));
        }
    }

    private Task<Result<JournalAppendClaim, JournalFailure>> AppendClaimed(JournalEntry entry)
    {
        entries.Add(entry);
        return Task.FromResult<Result<JournalAppendClaim, JournalFailure>>(
            new Result<JournalAppendClaim, JournalFailure>.Success(new(entry, true)));
    }
}

internal sealed class InMemoryRollbackAnchorStore : IRollbackAnchorStore
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

public sealed class PlatformRollbackAnchorStore : IRollbackAnchorStore
{
    // A TPM, device secure-store, or controller-signed checkpoint adapter is deliberately deferred.
    // The production journal remains unavailable rather than accepting a colocated filesystem fallback.
    public Task<Result<RollbackAnchor, JournalFailure>> ReadAsync(CancellationToken cancellationToken) =>
        Task.FromResult<Result<RollbackAnchor, JournalFailure>>(
            new Result<RollbackAnchor, JournalFailure>.Failure(
                new("rollback-anchor-platform-unavailable", "A TPM, device secure-store, or controller-signed rollback anchor is required before restoring the journal.")));

    public Task<Result<RollbackAnchor, JournalFailure>> AdvanceAsync(
        RollbackAnchor next,
        CancellationToken cancellationToken) =>
        Task.FromResult<Result<RollbackAnchor, JournalFailure>>(
            new Result<RollbackAnchor, JournalFailure>.Failure(
                new("rollback-anchor-platform-unavailable", "A TPM, device secure-store, or controller-signed rollback anchor is required before recording the journal.")));
}
