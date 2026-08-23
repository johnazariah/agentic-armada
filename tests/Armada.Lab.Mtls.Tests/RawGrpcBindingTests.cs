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

    public static IEnumerable<object[]> InvalidEnrollmentWires =>
    [
        ["unknown outer field", new byte[] { 0x78, 0x01 }],
        ["duplicate protocol_version field", new byte[] { 0x0A, 0x01, (byte)'a', 0x0A, 0x01, (byte)'b' }]
    ];

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

    private static Sha256Digest Digest(ReadOnlySpan<byte> bytes) =>
        Sha256Digest.Parse($"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}") is
            Result<Sha256Digest, ContractValidationError>.Success digest
            ? digest.Value
            : throw new InvalidOperationException();

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
