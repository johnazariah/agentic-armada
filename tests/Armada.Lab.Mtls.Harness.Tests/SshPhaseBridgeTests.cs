using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Armada.Application;
using Armada.Contracts;
using Armada.Lab.Mtls.LiveHarness;
using Armada.Lab.Mtls.WslClient;
using Proto = Armada.Contracts.V1Alpha1;

namespace Armada.Lab.Mtls.Harness.Tests;

public sealed class SshPhaseBridgeTests
{
    [Fact]
    public async Task Phase_one_stages_valid_helpers_and_parses_the_requested_canonical_public_frame()
    {
        var helperDirectory = CreateHelperDirectory(("z.helper", [3]), ("a.helper", [1, 2]));
        try
        {
            var options = Options(helperDirectory);
            var expected = DeviceFrame(options.NodeUid, options.IdentityEpoch);
            var staging = StageProcess();
            var phaseOne = new FakeSshPhaseProcess(completion: new(
                "WSL login notice\n" + ProtocolOutput(JsonSerializer.Serialize(expected, JsonOptions)),
                "",
                0));
            var invoker = new FakeSshProcessInvoker(staging, phaseOne);
            var bridge = new SshPhaseBridge(options, invoker);

            var frame = await bridge.RunPhaseOneAsync(CancellationToken.None);

            Assert.Equal(expected.NodeUid, frame.NodeUid);
            Assert.Equal(expected.IdentityEpoch, frame.IdentityEpoch);
            Assert.Equal(expected.SubjectPublicKeyInfo, frame.SubjectPublicKeyInfo);
            Assert.Equal(2, invoker.Started.Count);
            var stagingCommand = Assert.Single(staging.Lines);
            Assert.Contains("mkdir -p \"$root/helper\"", stagingCommand, StringComparison.Ordinal);
            Assert.Contains(ShellQuoted("$(stat -c '%u:%a' \"$root/helper\")"), stagingCommand, StringComparison.Ordinal);
            Assert.DoesNotContain("a.helper", stagingCommand, StringComparison.Ordinal);
            Assert.DoesNotContain("z.helper", stagingCommand, StringComparison.Ordinal);
            Assert.DoesNotContain("Armada.Lab.Mtls.WslClient.dll", stagingCommand, StringComparison.Ordinal);
            Assert.DoesNotContain(Convert.ToBase64String([1, 2]), stagingCommand, StringComparison.Ordinal);
            Assert.DoesNotContain(Convert.ToBase64String([3]), stagingCommand, StringComparison.Ordinal);
            Assert.DoesNotContain(Convert.ToBase64String([9, 8, 7]), stagingCommand, StringComparison.Ordinal);
            Assert.Contains("sha256sum --quiet --strict --check helper.manifest", stagingCommand, StringComparison.Ordinal);
            Assert.Contains("manifest:helper.manifest) target", stagingCommand, StringComparison.Ordinal);
            Assert.Contains("test ! -e \"$target\"", stagingCommand, StringComparison.Ordinal);
            var stagingPayload = Assert.Single(staging.Writes);
            Assert.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes("a.helper")), stagingPayload, StringComparison.Ordinal);
            Assert.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes("z.helper")), stagingPayload, StringComparison.Ordinal);
            Assert.Contains(Convert.ToBase64String([1, 2]), stagingPayload, StringComparison.Ordinal);
            Assert.Contains(Convert.ToBase64String([3]), stagingPayload, StringComparison.Ordinal);
            Assert.True(staging.Operations.IndexOf("write") < staging.Operations.IndexOf("complete"));
            Assert.Single(phaseOne.Lines);
            Assert.Single(phaseOne.Writes);
            var request = JsonSerializer.Deserialize<DeviceProvisioningRequest>(phaseOne.Writes[0], JsonOptions);
            Assert.NotNull(request);
            Assert.Equal(options.NodeUid, request.NodeUid);
            Assert.Equal(options.IdentityEpoch, request.IdentityEpoch);
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Phase_one_rejects_an_unexpected_but_otherwise_valid_public_frame()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var options = Options(helperDirectory);
            var invoker = new FakeSshProcessInvoker(
                StageProcess(),
                new FakeSshPhaseProcess(completion: new(
                    ProtocolOutput(JsonSerializer.Serialize(DeviceFrame(Guid.NewGuid(), options.IdentityEpoch), JsonOptions)),
                    "",
                    0)));

            await Assert.ThrowsAsync<IOException>(() =>
                new SshPhaseBridge(options, invoker).RunPhaseOneAsync(CancellationToken.None));
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Phase_one_rejects_an_oversized_output_before_parsing()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var options = Options(helperDirectory);
            var invoker = new FakeSshProcessInvoker(
                StageProcess(),
                new FakeSshPhaseProcess(completion: new(ProtocolOutput(new string(' ', 64 * 1024 + 1)), "", 0)));

            await Assert.ThrowsAsync<IOException>(() =>
                new SshPhaseBridge(options, invoker).RunPhaseOneAsync(CancellationToken.None));
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Phase_one_rejects_a_frame_with_oversized_public_material()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var options = Options(helperDirectory);
            var oversized = new DevicePublicFrame(
                options.NodeUid,
                options.IdentityEpoch,
                new byte[4097],
                new byte[32],
                [1],
                new byte[32]);
            var invoker = new FakeSshProcessInvoker(
                StageProcess(),
                new FakeSshPhaseProcess(completion: new(ProtocolOutput(JsonSerializer.Serialize(oversized, JsonOptions)), "", 0)));

            await Assert.ThrowsAsync<ArgumentException>(() =>
                new SshPhaseBridge(options, invoker).RunPhaseOneAsync(CancellationToken.None));
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Helper_staging_rejects_unsafe_names_before_starting_ssh()
    {
        var helperDirectory = CreateHelperDirectory(("unsafe;helper", [1]));
        try
        {
            var invoker = new FakeSshProcessInvoker();

            await Assert.ThrowsAsync<IOException>(() =>
                new SshPhaseBridge(Options(helperDirectory), invoker).RunPhaseOneAsync(CancellationToken.None));

            Assert.Empty(invoker.Started);
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Helper_staging_accepts_a_bounded_ssh_startup_preamble_with_an_exact_completion_receipt()
    {
        var helperDirectory = CreateHelperDirectory(("dependency.dll", [1, 2, 3]));
        try
        {
            var options = Options(helperDirectory);
            var staging = StageProcess(completion: new(
                "WSL startup notice\n" + ProtocolOutput(StageComplete),
                "",
                0));
            var phaseOne = new FakeSshPhaseProcess(completion: new(
                ProtocolOutput(JsonSerializer.Serialize(DeviceFrame(options.NodeUid, options.IdentityEpoch), JsonOptions)),
                "",
                0));

            await new SshPhaseBridge(options, new FakeSshProcessInvoker(staging, phaseOne))
                .RunPhaseOneAsync(CancellationToken.None);

            Assert.True(staging.Operations.IndexOf("write") < staging.Operations.IndexOf("complete"));
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Helper_staging_rejects_unexpected_output_after_its_completion_receipt()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var staging = StageProcess(completion: new(ProtocolOutput($"{StageComplete}\nunexpected\n"), "", 0));
            var invoker = new FakeSshProcessInvoker(staging);

            await Assert.ThrowsAsync<IOException>(() =>
                new SshPhaseBridge(Options(helperDirectory), invoker).RunPhaseOneAsync(CancellationToken.None));

            Assert.Single(invoker.Started);
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Helper_staging_rejects_a_partial_stage_without_its_completion_receipt()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var staging = StageProcess(completion: new("", "", 0));
            var invoker = new FakeSshProcessInvoker(staging);

            await Assert.ThrowsAsync<IOException>(() =>
                new SshPhaseBridge(Options(helperDirectory), invoker).RunPhaseOneAsync(CancellationToken.None));

            Assert.Single(invoker.Started);
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Helper_staging_rejects_an_oversized_ssh_startup_preamble_after_sending_the_payload()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var staging = StageProcess(completion: new(
                new string('x', 16 * 1024 + 1) + "\n" + ProtocolOutput(StageComplete),
                "",
                0));
            var invoker = new FakeSshProcessInvoker(staging);

            await Assert.ThrowsAsync<IOException>(() =>
                new SshPhaseBridge(Options(helperDirectory), invoker).RunPhaseOneAsync(CancellationToken.None));

            Assert.Contains("write", staging.Operations);
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Phase_two_refuses_a_tampered_dependency_before_starting_ssh_or_sending_the_secret()
        {
            var helperDirectory = CreateHelperDirectory(("Grpc.Net.Client.dll", [1, 2, 3]));
            try
            {
                var options = Options(helperDirectory);
                var invoker = new FakeSshProcessInvoker();
                var bridge = new SshPhaseBridge(options, invoker);
                File.WriteAllBytes(Path.Combine(helperDirectory, "Grpc.Net.Client.dll"), [9, 9, 9]);

                using var authority = Authority();
                await Assert.ThrowsAsync<IOException>(() => bridge.RunPhaseTwoAsync(
                    Claim(options), new RecordingIdentityRegistry(), PublicFrame(options), Secret(), authority, CancellationToken.None));

                Assert.Empty(invoker.Started);
            }
            finally
            {
                DeleteHelperDirectory(helperDirectory);
            }
    }

    [Fact]
    public void Trusted_manifest_rejects_missing_or_unexpected_or_symlinked_helper_files()
        {
            var helperDirectory = CreateHelperDirectory(("Armada.Contracts.dll", [1]));
            try
            {
                var manifest = CreateManifest(helperDirectory);
                File.Delete(Path.Combine(helperDirectory, "Armada.Contracts.dll"));
                Assert.Throws<IOException>(() => PublishedHelperManifest.LoadAndVerify(manifest, helperDirectory));

                File.WriteAllBytes(Path.Combine(helperDirectory, "Armada.Contracts.dll"), [1]);
                File.WriteAllBytes(Path.Combine(helperDirectory, "unexpected.dll"), [2]);
                Assert.Throws<IOException>(() => PublishedHelperManifest.LoadAndVerify(manifest, helperDirectory));

                File.Delete(Path.Combine(helperDirectory, "unexpected.dll"));
                File.Delete(Path.Combine(helperDirectory, "Armada.Contracts.dll"));
                File.CreateSymbolicLink(
                    Path.Combine(helperDirectory, "Armada.Contracts.dll"),
                    Path.Combine(helperDirectory, "Armada.Lab.Mtls.WslClient.dll"));
                Assert.Throws<IOException>(() => PublishedHelperManifest.LoadAndVerify(manifest, helperDirectory));
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Phase_two_rejects_an_invalid_revocation_readiness_response()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var options = Options(helperDirectory);
            var process = new FakeSshPhaseProcess(
                ProtocolLines(JsonSerializer.Serialize(
                    new ReadyForRevocation(ReadyForRevocation.ReadyState, 6, Proto.TransportRejectionCode.ReplayConflict),
                    JsonOptions)),
                new("", "", 0));
            var identities = new RecordingIdentityRegistry();

            using var authority = Authority();
            await Assert.ThrowsAsync<IOException>(() =>
                new SshPhaseBridge(options, new FakeSshProcessInvoker(process)).RunPhaseTwoAsync(
                    Claim(options), identities, PublicFrame(options), Secret(), authority, CancellationToken.None));

            Assert.Equal(0, identities.Revocations);
            Assert.DoesNotContain("revocation-confirmed", process.Lines);
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Phase_two_sends_the_secret_only_in_stdin_and_confirms_after_controller_revocation()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var options = Options(helperDirectory);
            var secret = Secret();
            var results = WslProbePlan.Create()
                .Select(static expected => new ProbeExecutionResult(expected.Kind, expected.Disposition, expected.RejectionCode))
                .ToArray();
            var process = new FakeSshPhaseProcess(
                ProtocolLines(JsonSerializer.Serialize(
                    new ReadyForRevocation(ReadyForRevocation.ReadyState, 4, Proto.TransportRejectionCode.ReplayConflict),
                    JsonOptions)),
                new(JsonSerializer.Serialize(results, JsonOptions), "remote diagnostics", 0));
            var identities = new RecordingIdentityRegistry(() =>
            {
                Assert.Equal(2, process.Lines.Count);
                Assert.DoesNotContain("revocation-confirmed", process.Lines);
            });
            process.OnComplete = () =>
            {
                Assert.Equal("revocation-confirmed", process.Lines[^1]);
                Assert.Equal(1, identities.Revocations);
            };

            using var authority = Authority();
            var evidence = await new SshPhaseBridge(options, new FakeSshProcessInvoker(process)).RunPhaseTwoAsync(
                Claim(options), identities, PublicFrame(options), secret, authority, CancellationToken.None);

            var secretBase64 = Convert.ToBase64String(secret);
            var invocation = SshInvocation.CreateStdinOnlyInvocation();
            Assert.Equal(["-T", LabHarnessCommandContract.SshHost], invocation.ArgumentList);
            Assert.DoesNotContain(secretBase64, invocation.ArgumentList);
            Assert.DoesNotContain(secretBase64, process.Lines[0], StringComparison.Ordinal);
            Assert.Contains(secretBase64, process.Lines[1], StringComparison.Ordinal);
            Assert.DoesNotContain(secretBase64, process.Completion.StandardOutput, StringComparison.Ordinal);
            Assert.DoesNotContain(secretBase64, process.Completion.StandardError, StringComparison.Ordinal);
            Assert.All(evidence, item =>
            {
                Assert.DoesNotContain(secretBase64, item.Name, StringComparison.Ordinal);
                Assert.DoesNotContain(secretBase64, item.Value, StringComparison.Ordinal);
            });
            Assert.Equal(results.Length, evidence.Count);
            Assert.Equal("probe-10", evidence[^1].Name);
            Assert.Equal("TransportRejected", evidence[^1].Value);
            Assert.True(process.Operations.IndexOf("line") < process.Operations.IndexOf("read"));
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Phase_two_rejects_incomplete_probe_results_without_returning_evidence()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var options = Options(helperDirectory);
            var process = new FakeSshPhaseProcess(
                ProtocolLines(JsonSerializer.Serialize(
                    new ReadyForRevocation(ReadyForRevocation.ReadyState, 4, Proto.TransportRejectionCode.ReplayConflict),
                    JsonOptions)),
                new("[]", "", 0));

            using var authority = Authority();
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                new SshPhaseBridge(options, new FakeSshProcessInvoker(process)).RunPhaseTwoAsync(
                    Claim(options), new RecordingIdentityRegistry(), PublicFrame(options), Secret(), authority, CancellationToken.None));
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Phase_two_rejects_oversized_results_before_parsing()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var options = Options(helperDirectory);
            var process = new FakeSshPhaseProcess(
                ProtocolLines(JsonSerializer.Serialize(
                    new ReadyForRevocation(ReadyForRevocation.ReadyState, 4, Proto.TransportRejectionCode.ReplayConflict),
                    JsonOptions)),
                new(new string(' ', 64 * 1024 + 1), "", 0));

            using var authority = Authority();
            await Assert.ThrowsAsync<IOException>(() =>
                new SshPhaseBridge(options, new FakeSshProcessInvoker(process)).RunPhaseTwoAsync(
                    Claim(options), new RecordingIdentityRegistry(), PublicFrame(options), Secret(), authority, CancellationToken.None));
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Cleanup_requires_remote_root_absence_and_propagates_ssh_failure()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var process = new FakeSshPhaseProcess(completion: new("", "ignored", 23));
            var bridge = new SshPhaseBridge(Options(helperDirectory), new FakeSshProcessInvoker(process));

            await Assert.ThrowsAsync<IOException>(() => bridge.CleanupAsync(CancellationToken.None));

            var command = Assert.Single(process.Lines);
            Assert.Contains("set -eu;", command, StringComparison.Ordinal);
            Assert.Contains("test ! -L \"$root\"", command, StringComparison.Ordinal);
            Assert.Contains("rm -rf -- \"$root\"", command, StringComparison.Ordinal);
            Assert.Contains("test ! -e \"$root\"", command, StringComparison.Ordinal);
            Assert.EndsWith(ShellQuoted($"/usr/bin/printf '%s\\n' {CleanupComplete}") + "'", command, StringComparison.Ordinal);
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    [Fact]
    public async Task Cleanup_accepts_an_idempotent_verified_absence_receipt()
    {
        var helperDirectory = CreateHelperDirectory();
        try
        {
            var process = new FakeSshPhaseProcess(completion: new(ProtocolOutput(CleanupComplete), "", 0));
            var bridge = new SshPhaseBridge(Options(helperDirectory), new FakeSshProcessInvoker(process));

            await bridge.CleanupAsync(CancellationToken.None);

            var command = Assert.Single(process.Lines);
            Assert.Contains("if test -e \"$root\" || test -L \"$root\"; then", command, StringComparison.Ordinal);
            Assert.Contains("test ! -L \"$root\"", command, StringComparison.Ordinal);
            Assert.Contains(ShellQuoted($"/usr/bin/printf '%s\\n' {CleanupComplete}"), command, StringComparison.Ordinal);
        }
        finally
        {
            DeleteHelperDirectory(helperDirectory);
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private const string ProtocolBegin = "ARMADA_C2_PROTOCOL_BEGIN";
    private const string StageComplete = "ARMADA_C2_STAGE_COMPLETE";
    private const string CleanupComplete = "ARMADA_C2_CLEANUP_COMPLETE";

    private static LabHarnessOptions Options(string helperDirectory) => new(
        IPAddress.Parse("192.0.2.20"),
        8443,
        9443,
        "armada_c2_0123456789abcdef0123456789abcdef",
        Path.Combine(AppContext.BaseDirectory, "evidence"),
        helperDirectory,
        CreateManifest(helperDirectory),
        Guid.Parse("01234567-89ab-cdef-0123-456789abcdef"),
        1);

    private static string CreateHelperDirectory(params (string Name, byte[] Contents)[] additionalFiles)
    {
        var directory = Path.Combine(AppContext.BaseDirectory, $"ssh-phase-bridge-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, "Armada.Lab.Mtls.WslClient.dll"), [9, 8, 7]);
        foreach (var (name, contents) in additionalFiles)
        {
            File.WriteAllBytes(Path.Combine(directory, name), contents);
        }

        return directory;
    }

    private static string CreateManifest(string helperDirectory)
    {
        var manifest = helperDirectory + ".manifest";
        if (!File.Exists(manifest))
        {
            var entries = Directory.EnumerateFiles(helperDirectory)
                .Select(path => new
                {
                    Name = Path.GetFileName(path),
                    Digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant()
                })
                .OrderBy(static entry => entry.Name, StringComparer.Ordinal)
                .Select(static entry => $"{entry.Digest}  {entry.Name}");
            File.WriteAllText(manifest, string.Join('\n', entries) + '\n', Encoding.ASCII);
        }

        return manifest;
    }

    private static FakeSshPhaseProcess StageProcess(
        IEnumerable<string>? startupLines = null,
        SshProcessResult? completion = null) =>
        new(
            startupLines,
            completion ?? new(ProtocolOutput(StageComplete), "", 0));

    private static IEnumerable<string> ProtocolLines(string line) => [ProtocolBegin, line];

    private static string ProtocolOutput(string output) => ProtocolBegin + '\n' + output;

    private static string ShellQuoted(string fragment) =>
        fragment.Replace("'", "'\"'\"'", StringComparison.Ordinal);

    private static void DeleteHelperDirectory(string helperDirectory)
    {
        Directory.Delete(helperDirectory, recursive: true);
        File.Delete(helperDirectory + ".manifest");
    }

    private static DevicePublicFrame DeviceFrame(Guid nodeUid, long identityEpoch)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return DevicePublicFrame.Create(
            nodeUid,
            identityEpoch,
            key.ExportSubjectPublicKeyInfo(),
            new CertificateRequest("CN=ssh-bridge", key, HashAlgorithmName.SHA256).CreateSigningRequest());
    }

    private static PublicDeviceFrame PublicFrame(LabHarnessOptions options)
    {
        var frame = DeviceFrame(options.NodeUid, options.IdentityEpoch);
        return new(
            frame.NodeUid,
            frame.IdentityEpoch,
            frame.SubjectPublicKeyInfo,
            frame.PublicKeySha256,
            frame.CertificateSigningRequest,
            frame.FrameSha256);
    }

    private static EnrollmentClaimReference Claim(LabHarnessOptions options)
    {
        var frame = PublicFrame(options);
        var parsed = Sha256Digest.Parse($"sha256:{Convert.ToHexString(frame.PublicKeySha256).ToLowerInvariant()}");
        return new(
            Guid.NewGuid(),
            new NodeUid(options.NodeUid),
            options.IdentityEpoch,
            ((Result<Sha256Digest, ContractValidationError>.Success)parsed).Value);
    }

    private static byte[] Secret() => Encoding.UTF8.GetBytes("secret-is-stdin-only-and-is-long-enough");

    private static X509Certificate2 Authority()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=ssh-bridge-authority", key, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
    }

    private sealed class FakeSshProcessInvoker(params FakeSshPhaseProcess[] processes) : ISshProcessInvoker
    {
        private readonly Queue<FakeSshPhaseProcess> processes = new(processes);
        public List<FakeSshPhaseProcess> Started { get; } = [];

        public Task<ISshPhaseProcess> StartAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var process = processes.Dequeue();
            Started.Add(process);
            return Task.FromResult<ISshPhaseProcess>(process);
        }
    }

    private sealed class FakeSshPhaseProcess(
        IEnumerable<string>? outputLines = null,
        SshProcessResult? completion = null) : ISshPhaseProcess
    {
        private readonly Queue<string> outputLines = new(outputLines ?? []);
        public List<string> Lines { get; } = [];
        public List<string> Writes { get; } = [];
        public List<string> Operations { get; } = [];
        public SshProcessResult Completion { get; } = completion ?? new("", "", 0);
        public Action? OnComplete { get; set; }

        public Task WriteLineAsync(string value, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Lines.Add(value);
            Operations.Add("line");
            return Task.CompletedTask;
        }

        public Task WriteAsync(string value, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Writes.Add(value);
            Operations.Add("write");
            return Task.CompletedTask;
        }

        public Task FlushAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Operations.Add("flush");
            return Task.CompletedTask;
        }

        public Task<string?> ReadLineAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Operations.Add("read");
            return Task.FromResult(outputLines.Count == 0 ? null : outputLines.Dequeue());
        }

        public Task<SshProcessResult> CompleteAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Operations.Add("complete");
            OnComplete?.Invoke();
            return Task.FromResult(Completion);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class RecordingIdentityRegistry(Action? onRevoke = null) : INodeIdentityRegistry
    {
        private readonly Action? onRevoke = onRevoke;
        public int Revocations { get; private set; }

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> ResolveAsync(
            NodeUid nodeUid,
            long identityEpoch,
            string certificateSerial,
            string certificateThumbprintSha256,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RegisterAsync(
            NodeIdentityBinding binding,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RevokeAsync(
            NodeUid nodeUid,
            long identityEpoch,
            string reason,
            Guid correlationId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            onRevoke?.Invoke();
            Revocations++;
            return Task.FromResult<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>>(
                new Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Success(
                    new(nodeUid, identityEpoch, null!, "serial", "thumbprint", DateTimeOffset.UtcNow.AddMinutes(1), true)));
        }
    }
}
