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
using Microsoft.Extensions.DependencyInjection;
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
        public CountingClaimStore Claims { get; }
        public CountingStateStore State { get; }
        public CountingIssuer Issuer { get; }

        public static async Task<LoopbackServer> StartAsync()
        {
            var certificate = Certificate();
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Listen(IPAddress.Loopback, 0, listen =>
                {
                    listen.Protocols = HttpProtocols.Http2;
                    listen.UseHttps(certificate);
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
                new RawNodeTransportService(new EmptyIdentityRegistry(), new EmptyReplayReceipts()));
            await application.StartAsync();

            var address = application.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!
                .Addresses.Single();
            var handler = new SocketsHttpHandler
            {
                SslOptions =
                {
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
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
