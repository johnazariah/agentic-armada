using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Armada.Lab.Mtls.WslClient;
using Proto = Armada.Contracts.V1Alpha1;

namespace Armada.Lab.Mtls.Harness.Tests;

public sealed class WslClientProtocolTests
{
    [Fact]
    public void Phase_one_persists_a_p256_key_and_integrity_bound_frame_under_the_verified_root()
    {
        var root = CreateRoot();
        try
        {
            var request = new DeviceProvisioningRequest(root, Guid.NewGuid(), 1);

            var frame = DeviceMaterialStore.Provision(request);
            var replay = DeviceMaterialStore.Provision(request);

            frame.Validate();
            Assert.Equal(frame.NodeUid, replay.NodeUid);
            Assert.Equal(frame.IdentityEpoch, replay.IdentityEpoch);
            Assert.Equal(frame.SubjectPublicKeyInfo, replay.SubjectPublicKeyInfo);
            Assert.Equal(frame.CertificateSigningRequest, replay.CertificateSigningRequest);
            Assert.Equal(frame.FrameSha256, replay.FrameSha256);
            var materialDirectory = Path.Combine(root, $"{frame.NodeUid:D}-{frame.IdentityEpoch}");
            Assert.True(File.Exists(Path.Combine(materialDirectory, "device-key.pkcs8")));
            Assert.True(File.Exists(Path.Combine(materialDirectory, "device.csr.der")));
            Assert.Empty(Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Public_frame_rejects_a_csr_for_another_key()
    {
        using var first = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var second = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var frame = DevicePublicFrame.Create(
            Guid.NewGuid(),
            1,
            first.ExportSubjectPublicKeyInfo(),
            new CertificateRequest("CN=other", second, HashAlgorithmName.SHA256).CreateSigningRequest());

        Assert.Throws<ArgumentException>(frame.Validate);
    }

    [Fact]
    public void Phase_two_rejects_persisted_key_material_that_does_not_match_the_public_frame_before_channel_use()
    {
        var root = CreateRoot();
        try
        {
            var frame = DeviceMaterialStore.Provision(new(root, Guid.NewGuid(), 1));
            using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            File.WriteAllBytes(
                Path.Combine(root, $"{frame.NodeUid:D}-{frame.IdentityEpoch}", "device-key.pkcs8"),
                other.ExportPkcs8PrivateKey());

            var configuration = Configuration(root, frame);
            Assert.Throws<ArgumentException>(() => PhaseTwoClient.Create(configuration));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Phase_two_constructs_its_raw_grpc_channel_without_network_access()
    {
        var root = CreateRoot();
        try
        {
            var frame = DeviceMaterialStore.Provision(new(root, Guid.NewGuid(), 1));
            using var authorityKey = RSA.Create(2048);
            var authorityRequest = new CertificateRequest("CN=offline-test-ca", authorityKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var authority = authorityRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
            using var client = PhaseTwoClient.Create(Configuration(root, frame, authority.Export(X509ContentType.Cert)));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Raw_grpc_contract_uses_the_exact_existing_paths_without_exporting_the_raw_frame()
    {
        Assert.Equal("armada.node.transport.v1alpha1.NodeEnrollment", WslGrpcPaths.EnrollmentService);
        Assert.Equal("Enroll", WslGrpcPaths.EnrollmentMethod);
        Assert.Equal("armada.node.transport.v1alpha1.NodeTransport", WslGrpcPaths.TransportService);
        Assert.Equal("Connect", WslGrpcPaths.TransportMethod);
        Assert.DoesNotContain(
            typeof(PhaseTwoClient).Assembly.GetExportedTypes(),
            type => type.Name == "RawFrame");
    }

    [Fact]
    public void Probe_plan_covers_all_required_offline_scenarios()
    {
        var plan = WslProbePlan.Create();

        Assert.Equal(
        [
            ProbeKind.Enrollment, ProbeKind.Hello, ProbeKind.Snapshot, ProbeKind.Inventory, ProbeKind.Health,
            ProbeKind.ExactReplay, ProbeKind.ChangedReplay, ProbeKind.WrongCertificateAuthority,
            ProbeKind.MismatchedCsrKey, ProbeKind.PostRevocation
        ],
        plan.Select(static probe => probe.Kind));
        Assert.Contains(plan, static probe => probe is
        {
            Kind: ProbeKind.ChangedReplay,
            Disposition: ProbeDisposition.TransportRejected,
            RejectionCode: Proto.TransportRejectionCode.ReplayConflict
        });
        Assert.Contains(plan, static probe => probe is
        {
            Kind: ProbeKind.PostRevocation,
            Disposition: ProbeDisposition.TransportRejected,
            RejectionCode: Proto.TransportRejectionCode.RevokedIdentity
        });
    }

    [Fact]
    public void Probe_response_interpretation_is_deterministic_without_network_access()
    {
        var accepted = new Proto.EnrollmentResponse
        {
            LeafCertificateDer = Google.Protobuf.ByteString.CopyFrom([1]),
            IssuingCaDer = Google.Protobuf.ByteString.CopyFrom([2])
        };
        var acknowledgement = new Proto.ControlToNode { TransportAck = new Proto.TransportAck() };
        var revoked = new Proto.ControlToNode
        {
            TransportRejection = new Proto.TransportRejection
            {
                Code = Proto.TransportRejectionCode.RevokedIdentity
            }
        };

        Assert.Equal(ProbeDisposition.EnrollmentAccepted, ProbeResponseInterpreter.Enrollment(accepted));
        Assert.Equal((ProbeDisposition.TransportAcknowledged, null), ProbeResponseInterpreter.Transport(acknowledgement));
        Assert.Equal(
            (ProbeDisposition.TransportRejected, Proto.TransportRejectionCode.RevokedIdentity),
            ProbeResponseInterpreter.Transport(revoked));
        Assert.Equal(ProbeDisposition.TlsRejected, ProbeResponseInterpreter.Failure(new HttpRequestException()));
    }

    [Fact]
    public void Envelope_factory_makes_exact_replay_byte_identical_and_changed_replay_payload_only()
    {
        var frame = Frame();
        var originalCsr = frame.CertificateSigningRequest.ToArray();
        var sequence = ProbeEnvelopeFactory.Create(frame, new DateTimeOffset(2026, 8, 27, 2, 0, 0, TimeSpan.Zero));
        var exact = Proto.NodeToControl.Parser.ParseFrom(sequence.ExactReplay);
        var changed = Proto.NodeToControl.Parser.ParseFrom(sequence.ChangedReplay);

        Assert.Equal(sequence.Hello, sequence.ExactReplay);
        Assert.Equal(exact.ProtocolVersion, changed.ProtocolVersion);
        Assert.Equal(exact.NodeUid, changed.NodeUid);
        Assert.Equal(exact.IdentityEpoch, changed.IdentityEpoch);
        Assert.Equal(exact.StreamEpoch, changed.StreamEpoch);
        Assert.Equal(exact.Sequence, changed.Sequence);
        Assert.Equal(exact.MessageId, changed.MessageId);
        Assert.Equal(exact.CorrelationId, changed.CorrelationId);
        Assert.Equal(exact.IdempotencyKey, changed.IdempotencyKey);
        Assert.Equal(exact.SentAt, changed.SentAt);
        Assert.Equal(exact.PayloadCase, changed.PayloadCase);
        Assert.Equal(exact.Hello.SchemaVersion, changed.Hello.SchemaVersion);
        Assert.Equal(exact.Hello.PayloadType, changed.Hello.PayloadType);
        Assert.NotEqual(exact.Hello.AgentVersion, changed.Hello.AgentVersion);

        var mismatched = ProbeEnvelopeFactory.CreateMismatchedFrame(frame);
        Assert.Equal(frame.SubjectPublicKeyInfo, mismatched.SubjectPublicKeyInfo);
        Assert.NotEqual(frame.CertificateSigningRequest, mismatched.CertificateSigningRequest);
        Assert.Throws<ArgumentException>(mismatched.Validate);
        Assert.Equal(originalCsr, frame.CertificateSigningRequest);
    }

    [Fact]
    public async Task Probe_runner_executes_the_full_sequence_through_an_injectable_offline_transport()
    {
        var frame = Frame();
        var originalCsr = frame.CertificateSigningRequest.ToArray();
        var trust = TrustBundle();
        var transport = new OfflineProbeTransport(trust);

        var results = await new WslProbeRunner(transport).RunAsync(
            frame,
            trust,
            new DateTimeOffset(2026, 8, 27, 2, 0, 0, TimeSpan.Zero),
            CancellationToken.None);

        Assert.Equal(WslProbePlan.Create().Select(static expectation => expectation.Kind), results.Select(static result => result.Kind));
        Assert.Equal(ProbeDisposition.EnrollmentAccepted, results[0].Disposition);
        Assert.All(results.Skip(1).Take(5), static result => Assert.Equal(ProbeDisposition.TransportAcknowledged, result.Disposition));
        Assert.Equal((ProbeDisposition.TransportRejected, Proto.TransportRejectionCode.ReplayConflict), (results[6].Disposition, results[6].RejectionCode));
        Assert.Equal(ProbeDisposition.TlsRejected, results[7].Disposition);
        Assert.Equal(ProbeDisposition.ClientRejected, results[8].Disposition);
        Assert.Equal((ProbeDisposition.TransportRejected, Proto.TransportRejectionCode.RevokedIdentity), (results[9].Disposition, results[9].RejectionCode));
        Assert.Equal(originalCsr, frame.CertificateSigningRequest);
        Assert.Equal(7, transport.Envelopes.Count);
        Assert.Equal(transport.Envelopes[0], transport.Envelopes[4]);
        Assert.NotEqual(transport.Envelopes[0], transport.Envelopes[5]);
        WslProbePlan.EnsureSatisfied(results);
    }

    private static PhaseTwoConfiguration Configuration(string root, DevicePublicFrame frame, byte[]? trustedCa = null) =>
        new(
            root,
            frame,
            new Uri("https://127.0.0.1:8443"),
            new Uri("https://127.0.0.1:9443"),
            Guid.NewGuid().ToString("D"),
            RandomNumberGenerator.GetBytes(32),
            trustedCa ?? [1]);

    private static DevicePublicFrame Frame()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return DevicePublicFrame.Create(
            Guid.NewGuid(),
            1,
            key.ExportSubjectPublicKeyInfo(),
            new CertificateRequest("CN=offline-probe", key, HashAlgorithmName.SHA256).CreateSigningRequest());
    }

    private static ProbeTrustBundle TrustBundle()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=offline-probe-ca", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        return new(certificate.Export(X509ContentType.Cert));
    }

    private static string CreateRoot()
    {
        var root = Path.Combine(AppContext.BaseDirectory, $"wsl-client-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        return root;
    }

    private sealed class OfflineProbeTransport(ProbeTrustBundle enrolledTrust) : IProbeTransportClient
    {
        private readonly ProbeTrustBundle enrolledTrust = enrolledTrust;
        public List<byte[]> Envelopes { get; } = [];
        private int openCount;

        public Task<Proto.EnrollmentResponse> EnrolAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new Proto.EnrollmentResponse
            {
                LeafCertificateDer = Google.Protobuf.ByteString.CopyFrom([1]),
                IssuingCaDer = Google.Protobuf.ByteString.CopyFrom([2])
            });

        public Task<IProbeDuplexConnection> OpenTransportAsync(
            Proto.EnrollmentResponse enrolment,
            ProbeTrustBundle trustBundle,
            CancellationToken cancellationToken)
        {
            openCount++;
            if (!trustBundle.TrustedCaDer.SequenceEqual(enrolledTrust.TrustedCaDer))
            {
                return Task.FromResult<IProbeDuplexConnection>(new OfflineConnection(Envelopes, null, new HttpRequestException()));
            }

            return Task.FromResult<IProbeDuplexConnection>(openCount switch
            {
                1 => new OfflineConnection(
                    Envelopes,
                [
                    Acknowledgement(), Acknowledgement(), Acknowledgement(),
                    Acknowledgement(), Acknowledgement(), Rejection(Proto.TransportRejectionCode.ReplayConflict)
                ]),
                3 => new OfflineConnection(Envelopes, [Rejection(Proto.TransportRejectionCode.RevokedIdentity)]),
                _ => throw new InvalidOperationException("Unexpected probe connection.")
            });
        }

        private static Proto.ControlToNode Acknowledgement() =>
            new() { TransportAck = new Proto.TransportAck() };

        private static Proto.ControlToNode Rejection(Proto.TransportRejectionCode code) =>
            new() { TransportRejection = new Proto.TransportRejection { Code = code } };
    }

    private sealed class OfflineConnection(
        List<byte[]> envelopes,
        IEnumerable<Proto.ControlToNode>? responses,
        Exception? writeException = null) : IProbeDuplexConnection
    {
        private readonly Queue<Proto.ControlToNode> responses = responses is null ? [] : new(responses);

        public Task WriteAsync(ReadOnlyMemory<byte> encodedEnvelope, CancellationToken cancellationToken)
        {
            if (writeException is not null)
            {
                return Task.FromException(writeException);
            }

            envelopes.Add(encodedEnvelope.ToArray());
            return Task.CompletedTask;
        }

        public Task<Proto.ControlToNode> ReadAsync(CancellationToken cancellationToken) =>
            responses.Count > 0
                ? Task.FromResult(responses.Dequeue())
                : Task.FromException<Proto.ControlToNode>(new InvalidOperationException("No response configured."));

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
