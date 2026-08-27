using System.Collections.Immutable;
using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Armada.Contracts;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Grpc.Net.Client;
using Proto = Armada.Contracts.V1Alpha1;

namespace Armada.Lab.Mtls.WslClient;

public sealed record DeviceProvisioningRequest(string VerifiedRemoteRoot, Guid NodeUid, long IdentityEpoch)
{
    public void Validate()
    {
        if (NodeUid == Guid.Empty || IdentityEpoch <= 0)
        {
            throw new ArgumentException("The node UID and identity epoch must be present.");
        }

        _ = DeviceMaterialStore.VerifyRemoteRoot(VerifiedRemoteRoot);
    }
}

public sealed record DevicePublicFrame(
    Guid NodeUid,
    long IdentityEpoch,
    byte[] SubjectPublicKeyInfo,
    byte[] PublicKeySha256,
    byte[] CertificateSigningRequest,
    byte[] FrameSha256)
{
    private const int DigestLength = 32;

    public static DevicePublicFrame Create(
        Guid nodeUid,
        long identityEpoch,
        byte[] subjectPublicKeyInfo,
        byte[] certificateSigningRequest)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(identityEpoch);
        ArgumentNullException.ThrowIfNull(subjectPublicKeyInfo);
        ArgumentNullException.ThrowIfNull(certificateSigningRequest);
        var keyDigest = SHA256.HashData(subjectPublicKeyInfo);
        return new(
            nodeUid,
            identityEpoch,
            subjectPublicKeyInfo,
            keyDigest,
            certificateSigningRequest,
            SHA256.HashData(CanonicalBytes(nodeUid, identityEpoch, subjectPublicKeyInfo, keyDigest, certificateSigningRequest)));
    }

    public void Validate()
    {
        if (NodeUid == Guid.Empty || IdentityEpoch <= 0 ||
            SubjectPublicKeyInfo.Length is 0 or > NodeTransportProtocol.MaximumPublicKeyBytes ||
            CertificateSigningRequest.Length is 0 or > NodeTransportProtocol.MaximumCsrBytes ||
            PublicKeySha256.Length != DigestLength || FrameSha256.Length != DigestLength)
        {
            throw new ArgumentException("The public device frame is structurally invalid.");
        }

        if (!CryptographicOperations.FixedTimeEquals(PublicKeySha256, SHA256.HashData(SubjectPublicKeyInfo)) ||
            !CryptographicOperations.FixedTimeEquals(
                FrameSha256,
                SHA256.HashData(CanonicalBytes(
                    NodeUid,
                    IdentityEpoch,
                    SubjectPublicKeyInfo,
                    PublicKeySha256,
                    CertificateSigningRequest))) ||
            !DeviceMaterialStore.CsrBindsToP256Key(CertificateSigningRequest, SubjectPublicKeyInfo))
        {
            throw new ArgumentException("The public device frame does not bind a P-256 key and CSR.");
        }
    }

    internal static byte[] CanonicalBytes(
        Guid nodeUid,
        long identityEpoch,
        byte[] subjectPublicKeyInfo,
        byte[] publicKeySha256,
        byte[] certificateSigningRequest)
    {
        var bytes = new byte[
            16 + sizeof(long) +
            sizeof(int) + subjectPublicKeyInfo.Length +
            sizeof(int) + publicKeySha256.Length +
            sizeof(int) + certificateSigningRequest.Length];
        var offset = 0;
        nodeUid.TryWriteBytes(bytes.AsSpan(offset, 16));
        offset += 16;
        BitConverter.TryWriteBytes(bytes.AsSpan(offset, sizeof(long)), identityEpoch);
        offset += sizeof(long);
        Write(subjectPublicKeyInfo);
        Write(publicKeySha256);
        Write(certificateSigningRequest);
        return bytes;

        void Write(byte[] value)
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(offset, sizeof(int)), value.Length);
            offset += sizeof(int);
            value.CopyTo(bytes, offset);
            offset += value.Length;
        }
    }
}

public static class DeviceMaterialStore
{
    public const string PublicFrameRelativePath = "device/public-frame.bin";
    private const UnixFileMode OwnerDirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public static DevicePublicFrame Provision(DeviceProvisioningRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Validate();

        var root = VerifyRemoteRoot(request.VerifiedRemoteRoot);
        var directory = RequireChild(root, "device");
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(directory);
        }
        else
        {
            Directory.CreateDirectory(directory, OwnerDirectoryMode);
        }
        VerifyOwnedDirectory(directory);

        var keyPath = RequireChild(directory, "device-key.pkcs8");
        var csrPath = RequireChild(directory, "device.csr.der");
        var framePath = RequireChild(root, PublicFrameRelativePath);
        var materialExists = File.Exists(keyPath) || File.Exists(csrPath) || File.Exists(framePath);
        if (materialExists && (!File.Exists(keyPath) || !File.Exists(csrPath) || !File.Exists(framePath)))
        {
            throw new IOException("Device key material is incomplete.");
        }

        if (!materialExists)
        {
            using var generated = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var key = generated.ExportPkcs8PrivateKey();
            var csr = new CertificateRequest(
                $"CN=armada-node-{request.NodeUid:D}",
                generated,
                HashAlgorithmName.SHA256).CreateSigningRequest();
            WriteOwnerOnly(keyPath, key);
            WriteOwnerOnly(csrPath, csr);
            var frame = DevicePublicFrame.Create(
                request.NodeUid,
                request.IdentityEpoch,
                generated.ExportSubjectPublicKeyInfo(),
                csr);
            frame.Validate();
            WriteOwnerOnly(framePath, JsonSerializer.SerializeToUtf8Bytes(frame, DevicePublicFrameJson.Options));
            CryptographicOperations.ZeroMemory(key);
        }

        var privateKey = File.ReadAllBytes(keyPath);
        try
        {
            var csr = File.ReadAllBytes(csrPath);
            using var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(privateKey, out var bytesRead);
            if (bytesRead != privateKey.Length)
            {
                throw new ArgumentException("The persisted device key is not canonical PKCS#8.");
            }

            var frame = DevicePublicFrame.Create(
                request.NodeUid,
                request.IdentityEpoch,
                key.ExportSubjectPublicKeyInfo(),
                csr);
            frame.Validate();
            var persistedFrame = ReadPublicFrame(framePath);
            if (!FramesMatch(frame, persistedFrame))
            {
                throw new ArgumentException("Persisted public frame does not match the requested device identity.");
            }

            return frame;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    public static string VerifyRemoteRoot(string root)
    {
        if (string.IsNullOrWhiteSpace(root) || !Path.IsPathFullyQualified(root))
        {
            throw new ArgumentException("The verified remote root must be an absolute path.", nameof(root));
        }

        var fullRoot = Path.GetFullPath(root);
        var info = new DirectoryInfo(fullRoot);
        if (!info.Exists || info.LinkTarget is not null)
        {
            throw new IOException("The verified remote root must be an existing non-link directory.");
        }

        for (var candidate = info.Parent; candidate is not null; candidate = candidate.Parent)
        {
            if (candidate.LinkTarget is not null)
            {
                throw new IOException("The verified remote root must not descend from a symbolic link.");
            }
        }

        if (!OperatingSystem.IsWindows() && File.GetUnixFileMode(fullRoot) != OwnerDirectoryMode)
        {
            throw new IOException("The verified remote root must be owner-only (0700).");
        }

        var fileSystemRoot = Path.GetPathRoot(info.FullName);
        return string.Equals(info.FullName, fileSystemRoot, StringComparison.Ordinal)
            ? info.FullName
            : info.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    internal static bool CsrBindsToP256Key(byte[] csr, byte[] expectedSpki)
    {
        try
        {
            using var expected = ECDsa.Create();
            expected.ImportSubjectPublicKeyInfo(expectedSpki, out var expectedBytesRead);
            if (expectedBytesRead != expectedSpki.Length || !IsP256(expected))
            {
                return false;
            }

            if (!IsCanonicalP256Spki(expectedSpki))
            {
                return false;
            }

            var request = CertificateRequest.LoadSigningRequest(
                csr,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default);
            using var csrKey = request.PublicKey.GetECDsaPublicKey();
            return csrKey is not null &&
                IsP256(csrKey) &&
                CryptographicOperations.FixedTimeEquals(
                    request.PublicKey.ExportSubjectPublicKeyInfo(),
                    expected.ExportSubjectPublicKeyInfo());
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    internal static ECDsa LoadMatchingPrivateKey(string verifiedRemoteRoot, DevicePublicFrame frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        frame.Validate();
        var root = VerifyRemoteRoot(verifiedRemoteRoot);
        var directory = RequireChild(root, "device");
        var keyPath = RequireChild(directory, "device-key.pkcs8");
        var csrPath = RequireChild(directory, "device.csr.der");
        var framePath = RequireChild(root, PublicFrameRelativePath);
        if (new DirectoryInfo(directory).LinkTarget is not null ||
            !File.Exists(keyPath) || !File.Exists(csrPath) || !File.Exists(framePath) ||
            new FileInfo(keyPath).LinkTarget is not null || new FileInfo(csrPath).LinkTarget is not null)
        {
            throw new IOException("Persisted device material is missing or substituted.");
        }
        VerifyOwnedDirectory(directory);
        VerifyOwnerOnlyFile(keyPath);
        VerifyOwnerOnlyFile(csrPath);
        if (!FramesMatch(frame, ReadPublicFrame(framePath)))
        {
            throw new ArgumentException("Persisted public frame does not match the supplied public frame.");
        }

        var keyBytes = File.ReadAllBytes(keyPath);
        try
        {
            var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(keyBytes, out var bytesRead);
            if (bytesRead != keyBytes.Length ||
                !CryptographicOperations.FixedTimeEquals(
                    key.ExportSubjectPublicKeyInfo(),
                    frame.SubjectPublicKeyInfo) ||
                !CryptographicOperations.FixedTimeEquals(File.ReadAllBytes(csrPath), frame.CertificateSigningRequest))
            {
                key.Dispose();
                throw new ArgumentException("Persisted key material does not match the public frame.");
            }

            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    private static bool IsP256(ECDsa key) =>
        string.Equals(
            key.ExportParameters(false).Curve.Oid.Value,
            ECCurve.NamedCurves.nistP256.Oid.Value,
            StringComparison.Ordinal);

    private static bool IsCanonicalP256Spki(byte[] spki)
    {
        try
        {
            var reader = new AsnReader(spki, AsnEncodingRules.DER);
            var subjectPublicKeyInfo = reader.ReadSequence();
            var algorithm = subjectPublicKeyInfo.ReadSequence();
            var algorithmOid = algorithm.ReadObjectIdentifier();
            var curveOid = algorithm.ReadObjectIdentifier();
            algorithm.ThrowIfNotEmpty();
            subjectPublicKeyInfo.ReadBitString(out _);
            subjectPublicKeyInfo.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            return algorithmOid == "1.2.840.10045.2.1" &&
                curveOid == "1.2.840.10045.3.1.7";
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static string RequireChild(string root, string name)
    {
        var child = Path.GetFullPath(Path.Combine(root, name));
        var prefix = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        if (!child.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new IOException("Refusing to access material outside the verified remote root.");
        }

        return child;
    }

    private static void VerifyOwnedDirectory(string directory)
    {
        if (new DirectoryInfo(directory).LinkTarget is not null)
        {
            throw new IOException("Device material directory must not be a symbolic link.");
        }

        if (!OperatingSystem.IsWindows())
        {
            if (File.GetUnixFileMode(directory) != OwnerDirectoryMode)
            {
                throw new IOException("Device material directory must be owner-only.");
            }
        }
    }

    private static void WriteOwnerOnly(string path, byte[] contents)
    {
        if (File.Exists(path) || new FileInfo(path).LinkTarget is not null)
        {
            throw new IOException("Refusing to replace persisted device material.");
        }

        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            stream.Write(contents);
            stream.Flush(flushToDisk: true);
        }

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, OwnerFileMode);
            if (File.GetUnixFileMode(path) != OwnerFileMode)
            {
                throw new IOException("Device material must be owner-only.");
            }
        }
    }

    public static string PublicFramePath(string verifiedRemoteRoot) =>
        RequireChild(VerifyRemoteRoot(verifiedRemoteRoot), PublicFrameRelativePath);

    private static DevicePublicFrame ReadPublicFrame(string path)
    {
        if (new FileInfo(path).LinkTarget is not null)
        {
            throw new IOException("Persisted public frame is a symbolic link.");
        }

        var frame = JsonSerializer.Deserialize<DevicePublicFrame>(File.ReadAllBytes(path), DevicePublicFrameJson.Options)
            ?? throw new ArgumentException("Persisted public frame is invalid.");
        frame.Validate();
        return frame;
    }

    private static bool FramesMatch(DevicePublicFrame left, DevicePublicFrame right) =>
        left.NodeUid == right.NodeUid &&
        left.IdentityEpoch == right.IdentityEpoch &&
        CryptographicOperations.FixedTimeEquals(left.SubjectPublicKeyInfo, right.SubjectPublicKeyInfo) &&
        CryptographicOperations.FixedTimeEquals(left.PublicKeySha256, right.PublicKeySha256) &&
        CryptographicOperations.FixedTimeEquals(left.CertificateSigningRequest, right.CertificateSigningRequest) &&
        CryptographicOperations.FixedTimeEquals(left.FrameSha256, right.FrameSha256);

    private static void VerifyOwnerOnlyFile(string path)
    {
        if (!OperatingSystem.IsWindows() && File.GetUnixFileMode(path) != OwnerFileMode)
        {
            throw new IOException("Persisted device material must be owner-only (0600).");
        }
    }
}

public sealed record PhaseTwoConfiguration(
    string VerifiedRemoteRoot,
    DevicePublicFrame Device,
    Uri EnrollmentEndpoint,
    Uri TransportEndpoint,
    string ClaimId,
    byte[] ClaimSecret,
    byte[] TrustedCaDer)
{
    public void Validate()
    {
        if (EnrollmentEndpoint is null || TransportEndpoint is null || ClaimSecret is null || TrustedCaDer is null ||
            !EnrollmentEndpoint.IsAbsoluteUri || !TransportEndpoint.IsAbsoluteUri ||
            EnrollmentEndpoint.Scheme != Uri.UriSchemeHttps || TransportEndpoint.Scheme != Uri.UriSchemeHttps ||
            !Guid.TryParseExact(ClaimId, "D", out var claim) || claim == Guid.Empty ||
            ClaimSecret.Length is < NodeTransportProtocol.MinimumClaimSecretBytes or > NodeTransportProtocol.MaximumClaimSecretBytes ||
            TrustedCaDer.Length == 0)
        {
            throw new ArgumentException("Phase two requires complete stdin-provided TLS and enrolment configuration.");
        }

        var enrollmentAddress = WslTlsValidation.RequireExactUnicastLiteral(EnrollmentEndpoint);
        var transportAddress = WslTlsValidation.RequireExactUnicastLiteral(TransportEndpoint);
        if (!enrollmentAddress.Equals(transportAddress))
        {
            throw new ArgumentException("Enrollment and transport endpoints must use the same exact unicast IP address.");
        }

        if (Device is null)
        {
            throw new ArgumentException("Phase two requires a public device frame.");
        }

        Device.Validate();
    }
}

public static class WslGrpcPaths
{
    public const string EnrollmentService = "armada.node.transport.v1alpha1.NodeEnrollment";
    public const string EnrollmentMethod = "Enroll";
    public const string TransportService = "armada.node.transport.v1alpha1.NodeTransport";
    public const string TransportMethod = "Connect";
}

public interface IProbeTransportClient
{
    Task<Proto.EnrollmentResponse> EnrolAsync(DevicePublicFrame device, CancellationToken cancellationToken);

    Task<IProbeDuplexConnection> OpenTransportAsync(
        Proto.EnrollmentResponse enrolment,
        ProbeTrustBundle trustBundle,
        CancellationToken cancellationToken);
}

public interface IProbeDuplexConnection : IAsyncDisposable
{
    Task WriteAsync(ReadOnlyMemory<byte> encodedEnvelope, CancellationToken cancellationToken);

    Task<Proto.ControlToNode> ReadAsync(CancellationToken cancellationToken);
}

public sealed record ReadyForRevocation(string State, int CompletedReportCount, Proto.TransportRejectionCode ReplayRejectionCode)
{
    public const string ReadyState = "ready-for-revocation";
}

public interface IRevocationPhase
{
    Task PublishReadyAsync(ReadyForRevocation ready, CancellationToken cancellationToken);

    Task WaitForConfirmationAsync(ReadyForRevocation ready, CancellationToken cancellationToken);
}

public sealed record ProbeTrustBundle(byte[] TrustedCaDer)
{
    public static ProbeTrustBundle CreateUnrelated()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=armada-probe-untrusted", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        return new(certificate.Export(X509ContentType.Cert));
    }

    public void Validate()
    {
        if (TrustedCaDer is null || TrustedCaDer.Length == 0)
        {
            throw new ArgumentException("A trust bundle must contain a CA certificate.");
        }

        using var certificate = X509CertificateLoader.LoadCertificate(TrustedCaDer);
        if (!certificate.SubjectName.RawData.SequenceEqual(certificate.IssuerName.RawData))
        {
            throw new ArgumentException("The probe trust bundle must contain a root certificate.");
        }
    }
}

public sealed class PhaseTwoClient : IDisposable, IProbeTransportClient
{
    private readonly PhaseTwoConfiguration configuration;
    private readonly ECDsa privateKey;
    private readonly GrpcChannel enrollmentChannel;
    private bool disposed;

    private PhaseTwoClient(PhaseTwoConfiguration configuration, ECDsa privateKey, GrpcChannel enrollmentChannel)
    {
        this.configuration = configuration;
        this.privateKey = privateKey;
        this.enrollmentChannel = enrollmentChannel;
    }

    public static PhaseTwoClient Create(PhaseTwoConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        configuration.Validate();
        var key = DeviceMaterialStore.LoadMatchingPrivateKey(configuration.VerifiedRemoteRoot, configuration.Device);
        try
        {
            return new PhaseTwoClient(
                configuration,
                key,
                CreateChannel(configuration.EnrollmentEndpoint, configuration.TrustedCaDer, null));
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    public Task<Proto.EnrollmentResponse> EnrolAsync(CancellationToken cancellationToken) =>
        EnrolAsync(configuration.Device, cancellationToken);

    public async Task<Proto.EnrollmentResponse> EnrolAsync(DevicePublicFrame device, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(device);
        device.Validate();
        var request = new Proto.EnrollmentRequest
        {
            ProtocolVersion = NodeTransportProtocol.Version,
            ClaimId = configuration.ClaimId,
            ClaimSecret = ByteString.CopyFrom(configuration.ClaimSecret),
            NodeUid = device.NodeUid.ToString("D"),
            IdentityEpoch = device.IdentityEpoch,
            DevicePublicKey = ByteString.CopyFrom(device.SubjectPublicKeyInfo),
            PublicKeySha256 = ByteString.CopyFrom(device.PublicKeySha256),
            CertificateSigningRequest = ByteString.CopyFrom(device.CertificateSigningRequest),
            Inventory = new Proto.EnrollmentInventory(),
            RequestId = Guid.NewGuid().ToString("D"),
            SentAt = Timestamp.FromDateTime(DateTime.UtcNow)
        };
        var call = enrollmentChannel.CreateCallInvoker().AsyncUnaryCall(
            RawGrpcMethods.Enrollment,
            null,
            new CallOptions(cancellationToken: cancellationToken),
            new RawFrame(request.ToByteArray()));
        return await call.ResponseAsync.ConfigureAwait(false);
    }

    public TransportProbeConnection OpenTransport(Proto.EnrollmentResponse enrolment, ProbeTrustBundle trustBundle)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(enrolment);
        ArgumentNullException.ThrowIfNull(trustBundle);
        trustBundle.Validate();
        if (enrolment.LeafCertificateDer.IsEmpty)
        {
            throw new ArgumentException("The enrolment response has no client certificate.", nameof(enrolment));
        }

        var certificate = X509CertificateLoader.LoadCertificate(enrolment.LeafCertificateDer.Span).CopyWithPrivateKey(privateKey);
        var channel = CreateChannel(configuration.TransportEndpoint, trustBundle.TrustedCaDer, certificate);
        try
        {
            var call = channel.CreateCallInvoker().AsyncDuplexStreamingCall(
                RawGrpcMethods.Transport,
                null,
                new CallOptions());
            return new TransportProbeConnection(channel, certificate, call);
        }
        catch
        {
            channel.Dispose();
            certificate.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        enrollmentChannel.Dispose();
        privateKey.Dispose();
    }

    private static GrpcChannel CreateChannel(Uri endpoint, byte[] trustedCaDer, X509Certificate2? clientCertificate)
    {
        var endpointAddress = WslTlsValidation.RequireExactUnicastLiteral(endpoint);
        var authority = X509CertificateLoader.LoadCertificate(trustedCaDer);
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
            {
                if (certificate is null)
                {
                    return false;
                }

                using var serverCertificate = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                return WslTlsValidation.IsTrustedServerCertificate(serverCertificate, authority, endpointAddress);
            }
        };
        if (clientCertificate is not null)
        {
            handler.ClientCertificates.Add(clientCertificate);
        }

        return GrpcChannel.ForAddress(endpoint, new GrpcChannelOptions
        {
            HttpHandler = handler,
            DisposeHttpClient = true
        });
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed, this);

    Task<Proto.EnrollmentResponse> IProbeTransportClient.EnrolAsync(
        DevicePublicFrame device,
        CancellationToken cancellationToken) =>
        EnrolAsync(device, cancellationToken);

    Task<IProbeDuplexConnection> IProbeTransportClient.OpenTransportAsync(
        Proto.EnrollmentResponse enrolment,
        ProbeTrustBundle trustBundle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IProbeDuplexConnection>(OpenTransport(enrolment, trustBundle));
    }

    private static class RawGrpcMethods
    {
        internal static readonly Method<RawFrame, Proto.EnrollmentResponse> Enrollment = new(
            MethodType.Unary,
            WslGrpcPaths.EnrollmentService,
            WslGrpcPaths.EnrollmentMethod,
            RawFrame.Marshaller,
            MessageMarshaller<Proto.EnrollmentResponse>.Instance);

        internal static readonly Method<RawFrame, Proto.ControlToNode> Transport = new(
            MethodType.DuplexStreaming,
            WslGrpcPaths.TransportService,
            WslGrpcPaths.TransportMethod,
            RawFrame.Marshaller,
            MessageMarshaller<Proto.ControlToNode>.Instance);
    }

    private sealed class MessageMarshaller<T> where T : IMessage<T>, new()
    {
        internal static readonly Marshaller<T> Instance = Marshallers.Create(
            static (message, context) =>
            {
                context.SetPayloadLength(message.CalculateSize());
                message.WriteTo(context.GetBufferWriter());
                context.Complete();
            },
            static context => new MessageParser<T>(() => new T()).ParseFrom(context.PayloadAsNewBuffer()));
    }
}

public static class WslTlsValidation
{
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    public static IPAddress RequireExactUnicastLiteral(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!IPAddress.TryParse(endpoint.DnsSafeHost, out var address) ||
            !IsUnicast(address))
        {
            throw new ArgumentException("TLS endpoints must use an exact unicast IP literal.", nameof(endpoint));
        }

        return address;
    }

    public static bool IsTrustedServerCertificate(
        X509Certificate2 serverCertificate,
        X509Certificate2 trustedRoot,
        IPAddress endpointAddress)
    {
        ArgumentNullException.ThrowIfNull(serverCertificate);
        ArgumentNullException.ThrowIfNull(trustedRoot);
        ArgumentNullException.ThrowIfNull(endpointAddress);

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(trustedRoot);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(serverCertificate) &&
            HasServerAuthenticationEku(serverCertificate) &&
            HasIpSubjectAlternativeName(serverCertificate, endpointAddress);
    }

    private static bool IsUnicast(IPAddress address)
    {
        if (IPAddress.Any.Equals(address) || IPAddress.IPv6Any.Equals(address) ||
            IPAddress.IPv6None.Equals(address) || IPAddress.IsLoopback(address))
        {
            return false;
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] < 224 &&
                !(bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255);
        }

        return !address.IsIPv6Multicast;
    }

    private static bool HasServerAuthenticationEku(X509Certificate2 certificate) =>
        certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(static extension => extension.EnhancedKeyUsages.Cast<Oid>())
            .Any(static oid => oid.Value == ServerAuthenticationOid);

    private static bool HasIpSubjectAlternativeName(X509Certificate2 certificate, IPAddress expectedAddress)
    {
        var extension = certificate.Extensions[SubjectAlternativeNameOid];
        if (extension is null)
        {
            return false;
        }

        try
        {
            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
            var names = reader.ReadSequence();
            while (names.HasData)
            {
                var tag = names.PeekTag();
                if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 7)))
                {
                    var address = new IPAddress(names.ReadOctetString(tag));
                    if (address.Equals(expectedAddress))
                    {
                        return true;
                    }
                }
                else
                {
                    names.ReadEncodedValue();
                }
            }

            reader.ThrowIfNotEmpty();
            return false;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }
}

public sealed class TransportProbeConnection : IProbeDuplexConnection
{
    private readonly GrpcChannel channel;
    private readonly X509Certificate2 certificate;
    private readonly AsyncDuplexStreamingCall<RawFrame, Proto.ControlToNode> call;

    internal TransportProbeConnection(
        GrpcChannel channel,
        X509Certificate2 certificate,
        AsyncDuplexStreamingCall<RawFrame, Proto.ControlToNode> call)
    {
        this.channel = channel;
        this.certificate = certificate;
        this.call = call;
    }

    public Task WriteAsync(ReadOnlyMemory<byte> encodedEnvelope, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return call.RequestStream.WriteAsync(new RawFrame(encodedEnvelope.ToArray()));
    }

    public async Task<Proto.ControlToNode> ReadAsync(CancellationToken cancellationToken)
    {
        if (!await call.ResponseStream.MoveNext(cancellationToken).ConfigureAwait(false))
        {
            throw new RpcException(new Status(StatusCode.Unavailable, "The transport stream closed without a response."));
        }

        return call.ResponseStream.Current;
    }

    public async ValueTask DisposeAsync()
    {
        await call.RequestStream.CompleteAsync().ConfigureAwait(false);
        call.Dispose();
        channel.Dispose();
        certificate.Dispose();
    }
}

public enum ProbeKind
{
    Enrollment,
    Hello,
    Snapshot,
    Inventory,
    Health,
    ExactReplay,
    ChangedReplay,
    WrongCertificateAuthority,
    MismatchedCsrKey,
    PostRevocation
}

public enum ProbeDisposition
{
    EnrollmentAccepted,
    TransportAcknowledged,
    TlsRejected,
    ControllerDenied,
    TransportRejected
}

public sealed record ProbeExpectation(ProbeKind Kind, ProbeDisposition Disposition, Proto.TransportRejectionCode? RejectionCode = null);

public static class WslProbePlan
{
    public static ImmutableArray<ProbeExpectation> Create() =>
    [
        new(ProbeKind.Enrollment, ProbeDisposition.EnrollmentAccepted),
        new(ProbeKind.Hello, ProbeDisposition.TransportAcknowledged),
        new(ProbeKind.Snapshot, ProbeDisposition.TransportAcknowledged),
        new(ProbeKind.Inventory, ProbeDisposition.TransportAcknowledged),
        new(ProbeKind.Health, ProbeDisposition.TransportAcknowledged),
        new(ProbeKind.ExactReplay, ProbeDisposition.TransportAcknowledged),
        new(ProbeKind.ChangedReplay, ProbeDisposition.TransportRejected, Proto.TransportRejectionCode.ReplayConflict),
        new(ProbeKind.WrongCertificateAuthority, ProbeDisposition.TlsRejected),
        new(ProbeKind.MismatchedCsrKey, ProbeDisposition.ControllerDenied),
        new(ProbeKind.PostRevocation, ProbeDisposition.TransportRejected, Proto.TransportRejectionCode.RevokedIdentity)
    ];

    public static void EnsureSatisfied(IReadOnlyList<ProbeExecutionResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);
        var expected = Create();
        if (results.Count != expected.Length)
        {
            throw new InvalidOperationException("The probe sequence did not produce every required result.");
        }

        for (var index = 0; index < expected.Length; index++)
        {
            if (results[index].Kind != expected[index].Kind ||
                results[index].Disposition != expected[index].Disposition ||
                results[index].RejectionCode != expected[index].RejectionCode)
            {
                throw new InvalidOperationException($"Probe '{expected[index].Kind}' did not produce its required result.");
            }
        }
    }
}

public sealed record ProbeEnvelopeSequence(
    byte[] Hello,
    byte[] Snapshot,
    byte[] Inventory,
    byte[] Health,
    byte[] ExactReplay,
    byte[] ChangedReplay,
    byte[] PostRevocation);

public static class ProbeEnvelopeFactory
{
    public static ProbeEnvelopeSequence Create(DevicePublicFrame device, DateTimeOffset sentAt)
    {
        ArgumentNullException.ThrowIfNull(device);
        device.Validate();
        var timestamp = Timestamp.FromDateTime(sentAt.UtcDateTime);
        var hello = Envelope(device, timestamp, "hello", 1, message =>
            message.Hello = new Proto.Hello
            {
                SchemaVersion = NodeTransportProtocol.Version,
                AgentVersion = "wsl-probe/1",
                PayloadType = NodeTransportProtocol.HelloPayloadType
            });
        var snapshot = Envelope(device, timestamp, "snapshot", 2, message =>
            message.FullReconciliationSnapshot = new Proto.FullReconciliationSnapshot
            {
                SchemaVersion = NodeTransportProtocol.Version,
                Snapshot = ByteString.CopyFrom([1]),
                PayloadType = NodeTransportProtocol.FullReconciliationSnapshotPayloadType
            });
        var inventory = Envelope(device, timestamp, "inventory", 3, message =>
        {
            var observed = new Proto.InventoryObservation
            {
                SchemaVersion = NodeTransportProtocol.Version,
                PayloadType = NodeTransportProtocol.InventoryObservationPayloadType
            };
            observed.Inventory = new Proto.EnrollmentInventory();
            observed.Inventory.Facts.Add("platform", "wsl");
            observed.Inventory.Capabilities.Add("probe");
            message.InventoryObservation = observed;
        });
        var health = Envelope(device, timestamp, "health", 4, message =>
            message.HealthObservation = new Proto.HealthObservation
            {
                SchemaVersion = NodeTransportProtocol.Version,
                StorageAvailable = true,
                PayloadType = NodeTransportProtocol.HealthObservationPayloadType
            });
        var exactReplay = hello;
        var changedReplay = Envelope(device, timestamp, "hello", 1, message =>
            message.Hello = new Proto.Hello
            {
                SchemaVersion = NodeTransportProtocol.Version,
                AgentVersion = "wsl-probe/changed",
                PayloadType = NodeTransportProtocol.HelloPayloadType
            });
        var postRevocation = Envelope(device, timestamp, "post-revocation", 5, message =>
            message.HealthObservation = new Proto.HealthObservation
            {
                SchemaVersion = NodeTransportProtocol.Version,
                StorageAvailable = false,
                PayloadType = NodeTransportProtocol.HealthObservationPayloadType
            });

        return new(hello, snapshot, inventory, health, exactReplay, changedReplay, postRevocation);
    }

    public static DevicePublicFrame CreateMismatchedFrame(DevicePublicFrame enrolled)
    {
        ArgumentNullException.ThrowIfNull(enrolled);
        enrolled.Validate();
        using var unrelatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var unrelatedCsr = new CertificateRequest(
            "CN=armada-probe-unrelated",
            unrelatedKey,
            HashAlgorithmName.SHA256).CreateSigningRequest();
        return DevicePublicFrame.Create(
            enrolled.NodeUid,
            enrolled.IdentityEpoch,
            unrelatedKey.ExportSubjectPublicKeyInfo(),
            unrelatedCsr);
    }

    private static byte[] Envelope(
        DevicePublicFrame device,
        Timestamp timestamp,
        string id,
        long sequence,
        Action<Proto.NodeToControl> setPayload)
    {
        var message = new Proto.NodeToControl
        {
            ProtocolVersion = NodeTransportProtocol.Version,
            NodeUid = device.NodeUid.ToString("D"),
            IdentityEpoch = device.IdentityEpoch,
            StreamEpoch = 1,
            Sequence = sequence,
            MessageId = DeterministicGuid(device.NodeUid, id).ToString("D"),
            CorrelationId = DeterministicGuid(device.NodeUid, "correlation").ToString("D"),
            IdempotencyKey = $"wsl-probe-{id}",
            SentAt = timestamp.Clone()
        };
        setPayload(message);
        return message.ToByteArray();
    }

    private static Guid DeterministicGuid(Guid nodeUid, string purpose)
    {
        var input = System.Text.Encoding.UTF8.GetBytes($"{nodeUid:D}|{purpose}");
        var hash = SHA256.HashData(input);
        return new Guid(hash.AsSpan(0, 16));
    }
}

public sealed record ProbeExecutionResult(
    ProbeKind Kind,
    ProbeDisposition Disposition,
    Proto.TransportRejectionCode? RejectionCode = null);

public sealed class WslProbeRunner(IProbeTransportClient client)
{
    private readonly IProbeTransportClient client = client ?? throw new ArgumentNullException(nameof(client));

    public async Task<ImmutableArray<ProbeExecutionResult>> RunAsync(
        DevicePublicFrame device,
        ProbeTrustBundle enrolledTrustBundle,
        IRevocationPhase revocationPhase,
        DateTimeOffset sentAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(enrolledTrustBundle);
        ArgumentNullException.ThrowIfNull(revocationPhase);
        device.Validate();
        enrolledTrustBundle.Validate();

        var results = ImmutableArray.CreateBuilder<ProbeExecutionResult>();
        Proto.EnrollmentResponse enrolment;
        try
        {
            enrolment = await client.EnrolAsync(device, cancellationToken).ConfigureAwait(false);
            results.Add(new(ProbeKind.Enrollment, ProbeResponseInterpreter.Enrollment(enrolment)));
        }
        catch (Exception exception)
        {
            results.Add(new(ProbeKind.Enrollment, ProbeResponseInterpreter.Failure(exception)));
            return results.ToImmutable();
        }

        var envelopes = ProbeEnvelopeFactory.Create(device, sentAt);
        await using (var connection = await client.OpenTransportAsync(enrolment, enrolledTrustBundle, cancellationToken).ConfigureAwait(false))
        {
            await SendAndRecordAsync(ProbeKind.Hello, envelopes.Hello, connection, results, cancellationToken).ConfigureAwait(false);
            await SendAndRecordAsync(ProbeKind.Snapshot, envelopes.Snapshot, connection, results, cancellationToken).ConfigureAwait(false);
            await SendAndRecordAsync(ProbeKind.Inventory, envelopes.Inventory, connection, results, cancellationToken).ConfigureAwait(false);
            await SendAndRecordAsync(ProbeKind.Health, envelopes.Health, connection, results, cancellationToken).ConfigureAwait(false);
            await SendAndRecordAsync(ProbeKind.ExactReplay, envelopes.ExactReplay, connection, results, cancellationToken).ConfigureAwait(false);
            await SendAndRecordAsync(ProbeKind.ChangedReplay, envelopes.ChangedReplay, connection, results, cancellationToken).ConfigureAwait(false);
        }

        var ready = CreateReadyForRevocation(results);
        await revocationPhase.PublishReadyAsync(ready, cancellationToken).ConfigureAwait(false);

        var wrongTrustBundle = ProbeTrustBundle.CreateUnrelated();
        try
        {
            await using var wrongCaConnection = await client
                .OpenTransportAsync(enrolment, wrongTrustBundle, cancellationToken)
                .ConfigureAwait(false);
            await SendAndRecordAsync(ProbeKind.WrongCertificateAuthority, envelopes.Hello, wrongCaConnection, results, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            results.Add(new(ProbeKind.WrongCertificateAuthority, ProbeResponseInterpreter.Failure(exception)));
        }

        var mismatched = ProbeEnvelopeFactory.CreateMismatchedFrame(device);
        mismatched.Validate();
        try
        {
            _ = await client.EnrolAsync(mismatched, cancellationToken).ConfigureAwait(false);
            results.Add(new(ProbeKind.MismatchedCsrKey, ProbeDisposition.EnrollmentAccepted));
        }
        catch (RpcException exception) when (exception.StatusCode == StatusCode.FailedPrecondition)
        {
            results.Add(new(ProbeKind.MismatchedCsrKey, ProbeDisposition.ControllerDenied));
        }
        catch (Exception exception)
        {
            results.Add(new(ProbeKind.MismatchedCsrKey, ProbeResponseInterpreter.Failure(exception)));
        }

        await revocationPhase.WaitForConfirmationAsync(ready, cancellationToken).ConfigureAwait(false);

        await using (var revokedConnection = await client.OpenTransportAsync(enrolment, enrolledTrustBundle, cancellationToken).ConfigureAwait(false))
        {
            await SendAndRecordAsync(
                ProbeKind.PostRevocation,
                envelopes.PostRevocation,
                revokedConnection,
                results,
                cancellationToken).ConfigureAwait(false);
        }

        return results.ToImmutable();
    }

    private static ReadyForRevocation CreateReadyForRevocation(ImmutableArray<ProbeExecutionResult>.Builder results)
    {
        var required = results
            .Where(static result => result.Kind is ProbeKind.Hello or ProbeKind.Snapshot or ProbeKind.Inventory or ProbeKind.Health)
            .ToArray();
        var changedReplay = results.SingleOrDefault(static result => result.Kind == ProbeKind.ChangedReplay);
        if (required.Length != 4 ||
            required.Any(static result => result.Disposition != ProbeDisposition.TransportAcknowledged) ||
            changedReplay is not
            {
                Disposition: ProbeDisposition.TransportRejected,
                RejectionCode: Proto.TransportRejectionCode.ReplayConflict
            })
        {
            throw new InvalidOperationException("The initial reports and changed replay must complete before revocation.");
        }

        return new(ReadyForRevocation.ReadyState, required.Length, changedReplay.RejectionCode.Value);
    }

    private static async Task SendAndRecordAsync(
        ProbeKind kind,
        byte[] envelope,
        IProbeDuplexConnection connection,
        ImmutableArray<ProbeExecutionResult>.Builder results,
        CancellationToken cancellationToken)
    {
        try
        {
            await connection.WriteAsync(envelope, cancellationToken).ConfigureAwait(false);
            var response = await connection.ReadAsync(cancellationToken).ConfigureAwait(false);
            var observed = ProbeResponseInterpreter.Transport(response);
            results.Add(new(kind, observed.Disposition, observed.RejectionCode));
        }
        catch (Exception exception)
        {
            results.Add(new(kind, ProbeResponseInterpreter.Failure(exception)));
        }
    }
}

public static class ProbeResponseInterpreter
{
    public static ProbeDisposition Enrollment(Proto.EnrollmentResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        return response.LeafCertificateDer.IsEmpty || response.IssuingCaDer.IsEmpty
            ? ProbeDisposition.TransportRejected
            : ProbeDisposition.EnrollmentAccepted;
    }

    public static (ProbeDisposition Disposition, Proto.TransportRejectionCode? RejectionCode) Transport(Proto.ControlToNode response)
    {
        ArgumentNullException.ThrowIfNull(response);
        return response.PayloadCase switch
        {
            Proto.ControlToNode.PayloadOneofCase.TransportAck => (ProbeDisposition.TransportAcknowledged, null),
            Proto.ControlToNode.PayloadOneofCase.TransportRejection =>
                (ProbeDisposition.TransportRejected, response.TransportRejection.Code),
            _ => (ProbeDisposition.TransportRejected, null)
        };
    }

    public static ProbeDisposition Failure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        if (exception is RpcException { StatusCode: StatusCode.FailedPrecondition })
        {
            return ProbeDisposition.ControllerDenied;
        }

        return exception is AuthenticationException or HttpRequestException
            ? ProbeDisposition.TlsRejected
            : ProbeDisposition.TransportRejected;
    }
}

internal static class DevicePublicFrameJson
{
    internal static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);
}
