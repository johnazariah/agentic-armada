using System.Collections.Immutable;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Armada.Application;
using Armada.Contracts;
using Armada.Lab.Mtls;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Google.Protobuf.WellKnownTypes;
using Proto = Armada.Contracts.V1Alpha1;

namespace Armada.Lab.Mtls.Tests;

public sealed class RawGrpcBindingTests
{
    [Theory]
    [MemberData(nameof(InvalidEnrollmentWires))]
    public async Task Invalid_outer_enrollment_wire_is_rejected_before_state_or_issuer(
        string _,
        byte[] wire)
    {
        await using var server = await LoopbackServer.StartAsync();
        var call = server.Client.CreateCallInvoker().AsyncUnaryCall(
            EnrollmentMethod,
            host: null,
            new CallOptions(),
            new RawGrpcMessage(ImmutableArray.CreateRange(wire)));

        var exception = await Assert.ThrowsAsync<RpcException>(async () => await call.ResponseAsync);

        Assert.Equal(StatusCode.InvalidArgument, exception.StatusCode);
        Assert.Equal(0, server.Claims.Calls);
        Assert.Equal(0, server.State.Calls);
        Assert.Equal(0, server.Issuer.Calls);
    }

    [Fact]
    public async Task Raw_binding_exposes_only_the_generated_grpc_routes()
    {
        await using var server = await LoopbackServer.StartAsync();

        var routes = server.Application.Services.GetRequiredService<IEnumerable<EndpointDataSource>>()
            .SelectMany(static source => source.Endpoints)
            .OfType<RouteEndpoint>()
            .Select(static endpoint => endpoint.RoutePattern.RawText)
            .Where(static route => route is not null && route.StartsWith("/armada.node.transport.v1alpha1.", StringComparison.Ordinal))
            .ToArray();

        Assert.Equal(
            [
                "/armada.node.transport.v1alpha1.NodeEnrollment/Enroll",
                "/armada.node.transport.v1alpha1.NodeTransport/Connect"
            ],
            routes.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Raw_unary_enrolment_reaches_state_issuer_and_completion_over_loopback_tls()
    {
        var now = TruncateToSecond(DateTimeOffset.UtcNow);
        var claimId = Guid.NewGuid();
        var nodeUid = new NodeUid(Guid.NewGuid());
        var requestId = Guid.NewGuid();
        const long epoch = 7;
        var claims = new RecordingEnrollmentClaimStore();
        var state = new RecordingEnrollmentStateStore();
        using var issuer = new RecordingCertificateIssuer();
        await using var server = await EnrollmentLoopbackServer.StartAsync(
            claims,
            state,
            issuer,
            new FixedTimeProvider(now));
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = deviceKey.ExportSubjectPublicKeyInfo();
        var certificateRequest = new CertificateRequest("CN=armada-node", deviceKey, HashAlgorithmName.SHA256);
        var request = new Proto.EnrollmentRequest
        {
            ProtocolVersion = NodeTransportProtocol.Version,
            ClaimId = claimId.ToString("D"),
            ClaimSecret = ByteString.CopyFrom(Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray()),
            NodeUid = nodeUid.ToString(),
            IdentityEpoch = epoch,
            DevicePublicKey = ByteString.CopyFrom(publicKey),
            PublicKeySha256 = ByteString.CopyFrom(SHA256.HashData(publicKey)),
            CertificateSigningRequest = ByteString.CopyFrom(certificateRequest.CreateSigningRequest()),
            RequestId = requestId.ToString("D"),
            SentAt = Timestamp.FromDateTimeOffset(now)
        };
        request.Inventory = new Proto.EnrollmentInventory();
        request.Inventory.Facts.Add("os", "linux");
        request.Inventory.Capabilities.Add("container");

        var call = server.Client.CreateCallInvoker().AsyncUnaryCall(
            EnrollmentMethod,
            host: null,
            new CallOptions(),
            new RawGrpcMessage(ImmutableArray.CreateRange(request.ToByteArray())));
        var response = await call.ResponseAsync;

        Assert.Equal(NodeTransportProtocol.Version, response.ProtocolVersion);
        Assert.Equal(nodeUid.ToString(), response.NodeUid);
        Assert.Equal(epoch, response.IdentityEpoch);
        Assert.NotEmpty(response.LeafCertificateDer);
        Assert.NotEmpty(response.IssuingCaDer);
        Assert.True(Guid.TryParseExact(response.CorrelationId, "D", out _));
        Assert.Equal(1, state.FindCompletedCalls);
        Assert.Equal(1, claims.ReserveCalls);
        Assert.Equal(1, issuer.Calls);
        Assert.Equal(1, state.CompleteCalls);
        Assert.Equal(claimId, claims.Reference!.ClaimId);
        Assert.Equal(nodeUid, claims.Reference.NodeUid);
        Assert.Equal(requestId, claims.RequestId);
        Assert.Equal(response.CertificateSerial, state.Completion!.Response.CertificateSerial);
        Assert.Equal(epoch, state.Completion.Identity.IdentityEpoch);
    }

    public static IEnumerable<object[]> InvalidEnrollmentWires =>
    [
        ["unknown outer field", new byte[] { 0x78, 0x01 }],
        ["duplicate protocol_version field", new byte[] { 0x0A, 0x01, (byte)'a', 0x0A, 0x01, (byte)'b' }],
        ["unknown inventory field", EnrollmentWithInventory([0x18, 0x01])],
        [
            "duplicate inventory map key",
            EnrollmentWithInventory(
                InventoryMapEntry("os", "linux")
                    .Concat(InventoryMapEntry("os", "ubuntu"))
                    .ToArray())
        ]
    ];

    [Fact]
    public void Composition_carries_the_validated_nondefault_certificate_lifetime_to_raw_enrolment()
    {
        using var certificate = Certificate();
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        var settings = new LabMtlsRuntimeSettings
        {
            Enabled = true,
            EnrollmentEndpoint = new(IPAddress.Parse("192.0.2.20"), 8443),
            StreamEndpoint = new(IPAddress.Parse("192.0.2.20"), 9443),
            ServerCertificate = certificate,
            ClientCertificateValidation = static (_, _, _) => true,
            CertificateLifetime = TimeSpan.FromHours(2)
        };
        var composition = LabMtlsAdapter.Compose(
            builder,
            settings,
            new(
                new ControllerEnrollmentStateService(new CountingClaimStore(), new CountingStateStore()),
                new CountingIssuer(),
                new EmptyIdentityRegistry(),
                new EmptyReplayReceipts()));

        Assert.Equal(TimeSpan.FromHours(2), composition.CreateEnrollmentService().CertificateLifetime);
    }

    [Theory]
    [InlineData("unknown field", new byte[] { 0x78, 0x01 })]
    [InlineData("duplicate protocol version", new byte[] { 0x0A, 0x01, (byte)'x' })]
    [InlineData("truncated field", new byte[] { 0x0A })]
    public async Task Invalid_raw_node_transport_wire_is_typed_rejection_before_identity_or_replay(
        string _,
        byte[] invalidSuffix)
    {
        var now = DateTimeOffset.UtcNow;
        var nodeUid = new NodeUid(Guid.NewGuid());
        var identities = new ThrowingIdentityRegistry();
        var receipts = new ThrowingReplayReceipts();
        await using var server = await LoopbackServer.StartAsync(identities, receipts, new FixedTimeProvider(now));
        var wire = Hello(nodeUid, now).ToByteArray().Concat(invalidSuffix).ToArray();

        var response = await ConnectAsync(server.Client, wire);

        Assert.Equal(Proto.ControlToNode.PayloadOneofCase.TransportRejection, response.PayloadCase);
        Assert.Equal(Proto.TransportRejectionCode.InvalidEnvelope, response.TransportRejection.Code);
        Assert.Equal(0, identities.Calls);
        Assert.Equal(0, receipts.Calls);
    }

    [Fact]
    public async Task Raw_node_transport_binding_accepts_mtls_hello_and_records_canonical_raw_identity()
    {
        var now = DateTimeOffset.UtcNow;
        var nodeUid = new NodeUid(Guid.NewGuid());
        var identities = new RecordingIdentityRegistry();
        var receipts = new RecordingReplayReceipts();
        await using var server = await LoopbackServer.StartAsync(identities, receipts, new FixedTimeProvider(now));
        identities.Binding = new(
            nodeUid,
            1,
            Digest(new byte[32]),
            server.Certificate.SerialNumber,
            Convert.ToHexString(server.Certificate.GetCertHash(HashAlgorithmName.SHA256)),
            now.AddHours(1),
            false);
        var wire = Hello(nodeUid, now).ToByteArray();
        var expected = NodeEnrollmentDecisions.ValidateTransportEnvelope(wire, now);
        var expectedIdentity =
            ((Result<ValidatedTransportEnvelope, NodeTransportValidationError>.Success)expected).Value.ReplayIdentity;

        var response = await ConnectAsync(server.Client, wire);

        Assert.Equal(Proto.ControlToNode.PayloadOneofCase.TransportAck, response.PayloadCase);
        Assert.Equal("accepted", response.TransportAck.Code);
        Assert.Equal(1, identities.Calls);
        Assert.Equal(1, receipts.Calls);
        Assert.NotNull(receipts.Receipt);
        Assert.Equal(expectedIdentity, receipts.Receipt.Identity);
        Assert.Equal(expectedIdentity.PayloadDigest, receipts.Receipt.Identity.PayloadDigest);
    }

    private static readonly Method<RawGrpcMessage, Proto.EnrollmentResponse> EnrollmentMethod =
        new(
            MethodType.Unary,
            "armada.node.transport.v1alpha1.NodeEnrollment",
            "Enroll",
            Marshallers.Create(
                static (message, context) =>
                {
                    context.SetPayloadLength(message.Bytes.Length);
                    context.Complete(message.Bytes.ToArray());
                },
                RawGrpcMessage.Read),
            Marshallers.Create(
                static (response, context) =>
                {
                    context.SetPayloadLength(response.CalculateSize());
                    response.WriteTo(context.GetBufferWriter());
                    context.Complete();
                },
                static context => Proto.EnrollmentResponse.Parser.ParseFrom(context.PayloadAsNewBuffer())));

    private static readonly Method<RawGrpcMessage, Proto.ControlToNode> TransportMethod =
        new(
            MethodType.DuplexStreaming,
            "armada.node.transport.v1alpha1.NodeTransport",
            "Connect",
            Marshallers.Create(
                static (message, context) =>
                {
                   context.SetPayloadLength(message.Bytes.Length);
                   context.Complete(message.Bytes.ToArray());
                },
                RawGrpcMessage.Read),
            Marshallers.Create(
                static (response, context) =>
                {
                   context.SetPayloadLength(response.CalculateSize());
                   response.WriteTo(context.GetBufferWriter());
                   context.Complete();
                },
                static context => Proto.ControlToNode.Parser.ParseFrom(context.PayloadAsNewBuffer())));

    private static async Task<Proto.ControlToNode> ConnectAsync(GrpcChannel client, byte[] wire)
    {
        using var call = client.CreateCallInvoker().AsyncDuplexStreamingCall(
            TransportMethod,
            host: null,
            new CallOptions());
        await call.RequestStream.WriteAsync(new RawGrpcMessage(ImmutableArray.CreateRange(wire)));
        await call.RequestStream.CompleteAsync();
        Assert.True(await call.ResponseStream.MoveNext(CancellationToken.None));
        return call.ResponseStream.Current;
    }

    private static Proto.NodeToControl Hello(NodeUid nodeUid, DateTimeOffset now) =>
        new()
        {
            ProtocolVersion = NodeTransportProtocol.Version,
            NodeUid = nodeUid.ToString(),
            IdentityEpoch = 1,
            StreamEpoch = 1,
            Sequence = 1,
            MessageId = Guid.NewGuid().ToString("D"),
            CorrelationId = Guid.NewGuid().ToString("D"),
            IdempotencyKey = "hello-1",
            SentAt = Timestamp.FromDateTimeOffset(now),
            Hello = new()
            {
                SchemaVersion = NodeTransportProtocol.Version,
                AgentVersion = "1.0.0",
                PayloadType = NodeTransportProtocol.HelloPayloadType
            }
        };

    private static byte[] EnrollmentWithInventory(byte[] inventory) =>
        [0x4A, checked((byte)inventory.Length), .. inventory];

    private static byte[] InventoryMapEntry(string key, string value)
    {
        var entry = new List<byte> { 0x0A, checked((byte)key.Length) };
        entry.AddRange(System.Text.Encoding.UTF8.GetBytes(key));
        entry.Add(0x12);
        entry.Add(checked((byte)value.Length));
        entry.AddRange(System.Text.Encoding.UTF8.GetBytes(value));
        return [0x0A, checked((byte)entry.Count), .. entry];
    }

    private static Sha256Digest Digest(ReadOnlySpan<byte> bytes) =>
        Sha256Digest.Parse($"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}") is
            Result<Sha256Digest, ContractValidationError>.Success digest
            ? digest.Value
            : throw new InvalidOperationException();

    private static DateTimeOffset TruncateToSecond(DateTimeOffset value) =>
        new(value.UtcDateTime.Year, value.UtcDateTime.Month, value.UtcDateTime.Day,
            value.UtcDateTime.Hour, value.UtcDateTime.Minute, value.UtcDateTime.Second, TimeSpan.Zero);

    private sealed class EnrollmentLoopbackServer : IAsyncDisposable
    {
        private readonly X509Certificate2 certificate;

        private EnrollmentLoopbackServer(WebApplication application, GrpcChannel client, X509Certificate2 certificate)
        {
            Application = application;
            Client = client;
            this.certificate = certificate;
        }

        public WebApplication Application { get; }
        public GrpcChannel Client { get; }

        public static async Task<EnrollmentLoopbackServer> StartAsync(
            IEnrollmentClaimStore claims,
            IEnrollmentStateStore state,
            ILabCertificateIssuer issuer,
            TimeProvider clock)
        {
            var certificate = Certificate();
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Listen(IPAddress.Loopback, 0, listen =>
                {
                    listen.Protocols = HttpProtocols.Http2;
                    listen.UseHttps(new HttpsConnectionAdapterOptions
                    {
                        ServerCertificate = certificate,
                        ClientCertificateMode = ClientCertificateMode.RequireCertificate,
                        ClientCertificateValidation = static (_, _, _) => true
                    });
                });
            });
            builder.Services.AddGrpc();

            var application = builder.Build();
            LabMtlsRawGrpcBinding.Map(
                application,
                new LabNodeEnrollmentGrpcService(
                    new ControllerEnrollmentStateService(claims, state),
                    issuer,
                    clock),
                new RawNodeTransportService(new EmptyIdentityRegistry(), new EmptyReplayReceipts(), clock));
            await application.StartAsync();

            var address = application.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!
                .Addresses.Single();
            var handler = new SocketsHttpHandler
            {
                SslOptions =
                {
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ClientCertificates = new X509CertificateCollection { certificate },
                    RemoteCertificateValidationCallback = static (_, _, _, _) => true
                }
            };
            return new(application, GrpcChannel.ForAddress(address, new GrpcChannelOptions { HttpHandler = handler }), certificate);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await Application.DisposeAsync();
            certificate.Dispose();
        }
    }

    private sealed class LoopbackServer : IAsyncDisposable
    {
        private readonly X509Certificate2 certificate;

        private LoopbackServer(
            WebApplication application,
            GrpcChannel client,
            X509Certificate2 certificate,
            CountingClaimStore claims,
            CountingStateStore state,
            CountingIssuer issuer)
        {
            Application = application;
            Client = client;
            this.certificate = certificate;
            Claims = claims;
            State = state;
            Issuer = issuer;
        }

        public WebApplication Application { get; }
        public GrpcChannel Client { get; }
        public X509Certificate2 Certificate => certificate;
        public CountingClaimStore Claims { get; }
        public CountingStateStore State { get; }
        public CountingIssuer Issuer { get; }

        public static async Task<LoopbackServer> StartAsync(
            INodeIdentityRegistry? identities = null,
            ITransportReplayReceiptStore? receipts = null,
            TimeProvider? clock = null)
        {
            var certificate = Certificate();
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Listen(IPAddress.Loopback, 0, listen =>
                {
                    listen.Protocols = HttpProtocols.Http2;
                    listen.UseHttps(new HttpsConnectionAdapterOptions
                    {
                        ServerCertificate = certificate,
                        ClientCertificateMode = ClientCertificateMode.RequireCertificate,
                        ClientCertificateValidation = static (_, _, _) => true
                    });
                });
            });
            builder.Services.AddGrpc();

            var claims = new CountingClaimStore();
            var state = new CountingStateStore();
            var issuer = new CountingIssuer();
            var application = builder.Build();
            LabMtlsRawGrpcBinding.Map(
                application,
                new LabNodeEnrollmentGrpcService(
                    new ControllerEnrollmentStateService(claims, state),
                    issuer),
                new RawNodeTransportService(
                    identities ?? new EmptyIdentityRegistry(),
                    receipts ?? new EmptyReplayReceipts(),
                    clock));
            await application.StartAsync();

            var address = application.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!
                .Addresses.Single();
            var handler = new SocketsHttpHandler
            {
                SslOptions =
                {
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ClientCertificates = new X509CertificateCollection { certificate },
                    RemoteCertificateValidationCallback = static (_, _, _, _) => true
                }
            };
            var client = GrpcChannel.ForAddress(address, new GrpcChannelOptions { HttpHandler = handler });
            return new(application, client, certificate, claims, state, issuer);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await Application.DisposeAsync();
            certificate.Dispose();
        }
    }

    private sealed class CountingClaimStore : IEnrollmentClaimStore
    {
        public int Calls { get; private set; }

        public Task<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>> GetAsync(
            Guid claimId,
            CancellationToken cancellationToken) => Unexpected<EnrollmentClaimState>();

        public Task<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>> VerifyAsync(
            EnrollmentClaimReference reference,
            ReadOnlyMemory<byte> presentedSecret,
            DateTimeOffset now,
            CancellationToken cancellationToken) => Unexpected<EnrollmentClaimState>();

        public Task<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>> ReserveAsync(
            EnrollmentClaimReference reference,
            ReadOnlyMemory<byte> presentedSecret,
            Guid requestId,
            DateTimeOffset now,
            CancellationToken cancellationToken) => Unexpected<EnrollmentClaimReservation>();

        public Task<Result<EnrollmentClaimConsumption, EnrollmentClaimStoreFailure>> ConsumeAsync(
            EnrollmentClaimReference reference,
            ReadOnlyMemory<byte> presentedSecret,
            CancellationToken cancellationToken) => Unexpected<EnrollmentClaimConsumption>();

        private Task<Result<T, EnrollmentClaimStoreFailure>> Unexpected<T>()
        {
            Calls++;
            throw new InvalidOperationException("Enrollment state must not be called for invalid raw protobuf.");
        }
    }

    private sealed class CountingStateStore : IEnrollmentStateStore
    {
        public int Calls { get; private set; }

        public Task<Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>> FindCompletedAsync(
            EnrollmentClaimReference claim,
            ReadOnlyMemory<byte> presentedSecret,
            CancellationToken cancellationToken) => Unexpected<EnrollmentCompletion?>();

        public Task<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>> CompleteAsync(
            EnrollmentCompletionRequest request,
            CancellationToken cancellationToken) => Unexpected<EnrollmentCompletion>();

        private Task<Result<T, EnrollmentStateStoreFailure>> Unexpected<T>()
        {
            Calls++;
            throw new InvalidOperationException("Enrollment state must not be called for invalid raw protobuf.");
        }
    }

    private sealed class CountingIssuer : ILabCertificateIssuer
    {
        public int Calls { get; private set; }

        public Task<Result<IssuedCertificate, CertificateIssuanceFailure>> IssueAsync(
            CertificateIssuanceRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("Certificate issuer must not be called for invalid raw protobuf.");
        }
    }

    private sealed class RecordingEnrollmentClaimStore : IEnrollmentClaimStore
    {
        public int ReserveCalls { get; private set; }
        public EnrollmentClaimReference? Reference { get; private set; }
        public Guid RequestId { get; private set; }

        public Task<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>> GetAsync(
            Guid claimId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<Result<EnrollmentClaimState, EnrollmentClaimStoreFailure>> VerifyAsync(
            EnrollmentClaimReference reference,
            ReadOnlyMemory<byte> presentedSecret,
            DateTimeOffset now,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>> ReserveAsync(
            EnrollmentClaimReference reference,
            ReadOnlyMemory<byte> presentedSecret,
            Guid requestId,
            DateTimeOffset now,
            CancellationToken cancellationToken)
        {
            ReserveCalls++;
            Reference = reference;
            RequestId = requestId;
            var claim = new EnrollmentClaimState(reference, now.AddMinutes(5), false);
            return Task.FromResult<Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>>(
                new Result<EnrollmentClaimReservation, EnrollmentClaimStoreFailure>.Success(
                    new EnrollmentClaimReservation(claim, requestId, now.AddMinutes(1))));
        }

        public Task<Result<EnrollmentClaimConsumption, EnrollmentClaimStoreFailure>> ConsumeAsync(
            EnrollmentClaimReference reference,
            ReadOnlyMemory<byte> presentedSecret,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class RecordingEnrollmentStateStore : IEnrollmentStateStore
    {
        public int FindCompletedCalls { get; private set; }
        public int CompleteCalls { get; private set; }
        public EnrollmentCompletionRequest? Completion { get; private set; }

        public Task<Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>> FindCompletedAsync(
            EnrollmentClaimReference claim,
            ReadOnlyMemory<byte> presentedSecret,
            CancellationToken cancellationToken)
        {
            FindCompletedCalls++;
            return Task.FromResult<Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>>(
                new Result<EnrollmentCompletion?, EnrollmentStateStoreFailure>.Success(null));
        }

        public Task<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>> CompleteAsync(
            EnrollmentCompletionRequest request,
            CancellationToken cancellationToken)
        {
            CompleteCalls++;
            Completion = request;
            return Task.FromResult<Result<EnrollmentCompletion, EnrollmentStateStoreFailure>>(
                new Result<EnrollmentCompletion, EnrollmentStateStoreFailure>.Success(
                    new EnrollmentCompletion.Completed(request.Response, request.Identity)));
        }
    }

    private sealed class RecordingCertificateIssuer : ILabCertificateIssuer, IDisposable
    {
        private readonly ECDsa certificateAuthorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly X509Certificate2 certificateAuthority;

        public RecordingCertificateIssuer()
        {
            var request = new CertificateRequest(
                "CN=armada-enrollment-test-ca",
                certificateAuthorityKey,
                HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            certificateAuthority = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(1));
        }

        public int Calls { get; private set; }

        public Task<Result<IssuedCertificate, CertificateIssuanceFailure>> IssueAsync(
            CertificateIssuanceRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            var leafRequest = CertificateRequest.LoadSigningRequest(
                request.Enrollment.CertificateSigningRequest.ToArray(),
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.Default,
                RSASignaturePadding.Pkcs1);
            leafRequest.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") },
                    false));
            var san = new SubjectAlternativeNameBuilder();
            san.AddUri(new Uri(
                $"spiffe://armada.lab/node/{request.Enrollment.NodeUid}/epoch/{request.Enrollment.IdentityEpoch}"));
            leafRequest.CertificateExtensions.Add(san.Build());
            using var leaf = leafRequest.Create(
                certificateAuthority,
                request.NotBefore,
                request.ExpiresAt,
                RandomNumberGenerator.GetBytes(16));
            var issued = new IssuedCertificate(
                leaf.SerialNumber,
                ImmutableArray.CreateRange(leaf.Export(X509ContentType.Cert)),
                ImmutableArray.CreateRange(certificateAuthority.Export(X509ContentType.Cert)),
                request.ExpiresAt);
            return Task.FromResult<Result<IssuedCertificate, CertificateIssuanceFailure>>(
                new Result<IssuedCertificate, CertificateIssuanceFailure>.Success(issued));
        }

        public void Dispose()
        {
            certificateAuthority.Dispose();
            certificateAuthorityKey.Dispose();
        }
    }

    private sealed class EmptyIdentityRegistry : INodeIdentityRegistry
    {
        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> ResolveAsync(
            NodeUid nodeUid,
            long identityEpoch,
            string certificateSerial,
            string certificateThumbprintSha256,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RegisterAsync(
            NodeIdentityBinding binding,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RevokeAsync(
            NodeUid nodeUid,
            long identityEpoch,
            string reason,
            Guid correlationId,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class EmptyReplayReceipts : ITransportReplayReceiptStore
    {
        public Task<Result<ReplayReceipt, ReplayReceiptStoreFailure>> RetrieveOrRecordAsync(
            ReplayReceipt receipt,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class ThrowingIdentityRegistry : INodeIdentityRegistry
    {
        public int Calls { get; private set; }

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> ResolveAsync(
            NodeUid nodeUid,
            long identityEpoch,
            string certificateSerial,
            string certificateThumbprintSha256,
            CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("Identity lookup must not occur for an invalid raw protobuf.");
        }

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RegisterAsync(
            NodeIdentityBinding binding,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RevokeAsync(
            NodeUid nodeUid,
            long identityEpoch,
            string reason,
            Guid correlationId,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class RecordingIdentityRegistry : INodeIdentityRegistry
    {
        public int Calls { get; private set; }
        public NodeIdentityBinding? Binding { get; set; }

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> ResolveAsync(
            NodeUid nodeUid,
            long identityEpoch,
            string certificateSerial,
            string certificateThumbprintSha256,
            CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>>(
                Binding is { } binding
                    ? new Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Success(binding)
                    : new Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Failure(new("not-found", "Not found.")));
        }

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RegisterAsync(
            NodeIdentityBinding binding,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RevokeAsync(
            NodeUid nodeUid,
            long identityEpoch,
            string reason,
            Guid correlationId,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class ThrowingReplayReceipts : ITransportReplayReceiptStore
    {
        public int Calls { get; private set; }

        public Task<Result<ReplayReceipt, ReplayReceiptStoreFailure>> RetrieveOrRecordAsync(
            ReplayReceipt receipt,
            CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("Replay recording must not occur for an invalid raw protobuf.");
        }
    }

    private sealed class RecordingReplayReceipts : ITransportReplayReceiptStore
    {
        public int Calls { get; private set; }
        public ReplayReceipt? Receipt { get; private set; }

        public Task<Result<ReplayReceipt, ReplayReceiptStoreFailure>> RetrieveOrRecordAsync(
            ReplayReceipt receipt,
            CancellationToken cancellationToken)
        {
            Calls++;
            Receipt = receipt;
            return Task.FromResult<Result<ReplayReceipt, ReplayReceiptStoreFailure>>(
                new Result<ReplayReceipt, ReplayReceiptStoreFailure>.Success(receipt));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static X509Certificate2 Certificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
                false));
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5));
        return X509CertificateLoader.LoadPkcs12(
            generated.Export(X509ContentType.Pfx),
            password: null,
            X509KeyStorageFlags.Exportable);
    }
}
