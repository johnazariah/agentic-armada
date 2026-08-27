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

    private static PhaseTwoConfiguration Configuration(string root, DevicePublicFrame frame, byte[]? trustedCa = null) =>
        new(
            root,
            frame,
            new Uri("https://127.0.0.1:8443"),
            new Uri("https://127.0.0.1:9443"),
            Guid.NewGuid().ToString("D"),
            RandomNumberGenerator.GetBytes(32),
            trustedCa ?? [1]);

    private static string CreateRoot()
    {
        var root = Path.Combine(AppContext.BaseDirectory, $"wsl-client-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        return root;
    }
}
