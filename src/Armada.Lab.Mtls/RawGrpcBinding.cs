using System.Collections.Immutable;
using Armada.Contracts;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Proto = Armada.Contracts.V1Alpha1;

namespace Armada.Lab.Mtls;

internal sealed record RawGrpcMessage(ImmutableArray<byte> Bytes)
{
    public static RawGrpcMessage Read(DeserializationContext context) =>
        new(ImmutableArray.CreateRange(context.PayloadAsNewBuffer()));
}

internal static class LabMtlsRawGrpcBinding
{
    private const string ServiceNamespace = "armada.node.transport.v1alpha1";

    private static readonly Marshaller<RawGrpcMessage> RawRequestMarshaller =
        Marshallers.Create(
            static (message, context) =>
            {
                context.SetPayloadLength(message.Bytes.Length);
                context.Complete(message.Bytes.ToArray());
            },
            RawGrpcMessage.Read);

    private static readonly Marshaller<Proto.EnrollmentResponse> EnrollmentResponseMarshaller =
        MessageMarshaller<Proto.EnrollmentResponse>.Instance;

    private static readonly Marshaller<Proto.ControlToNode> ControlToNodeMarshaller =
        MessageMarshaller<Proto.ControlToNode>.Instance;

    internal static void Map(
        WebApplication application,
        LabNodeEnrollmentGrpcService enrollment,
        RawNodeTransportService transport)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentNullException.ThrowIfNull(enrollment);
        ArgumentNullException.ThrowIfNull(transport);

        application.MapGrpcService(Build(enrollment, transport));
    }

    internal static ServerServiceDefinition Build(
        LabNodeEnrollmentGrpcService enrollment,
        RawNodeTransportService transport)
    {
        var enrol = new Method<RawGrpcMessage, Proto.EnrollmentResponse>(
            MethodType.Unary,
            $"{ServiceNamespace}.NodeEnrollment",
            "Enroll",
            RawRequestMarshaller,
            EnrollmentResponseMarshaller);
        var connect = new Method<RawGrpcMessage, Proto.ControlToNode>(
            MethodType.DuplexStreaming,
            $"{ServiceNamespace}.NodeTransport",
            "Connect",
            RawRequestMarshaller,
            ControlToNodeMarshaller);

        return ServerServiceDefinition.CreateBuilder()
            .AddMethod(enrol, enrollment.EnrollRawAsync)
            .AddMethod(connect, new DuplexStreamingServerMethod<RawGrpcMessage, Proto.ControlToNode>(
                async (requests, responses, context) =>
            {
                var certificate = await context.GetHttpContext()
                    .Connection.GetClientCertificateAsync(context.CancellationToken);
                if (certificate is null)
                {
                    throw new RpcException(new Status(StatusCode.Unauthenticated, "A client certificate is required."));
                }

                while (await requests.MoveNext(context.CancellationToken))
                {
                    var response = await transport.ProcessAsync(
                        requests.Current.Bytes.ToArray(),
                        certificate,
                        context.CancellationToken);
                    await responses.WriteAsync(response);
                    if (response.PayloadCase == Proto.ControlToNode.PayloadOneofCase.TransportRejection)
                    {
                        return;
                    }
                }
            }))
            .Build();
    }

    private sealed class MessageMarshaller<T> where T : IMessage<T>, new()
    {
        public static readonly Marshaller<T> Instance = Marshallers.Create(
            static (message, context) =>
            {
                context.SetPayloadLength(message.CalculateSize());
                message.WriteTo(context.GetBufferWriter());
                context.Complete();
            },
            static context => new MessageParser<T>(() => new T()).ParseFrom(context.PayloadAsNewBuffer()));
    }
}
