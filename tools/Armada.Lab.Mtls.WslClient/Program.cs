using Armada.Lab.Mtls.WslClient;
using Google.Protobuf;
using Grpc.Core;
using Proto = Armada.Contracts.V1Alpha1;

if (args.Length == 0 || args[0] is "--help" or "help")
{
    Console.WriteLine("Private C2 WSL helper. phase-one and phase-two are invoked only by the reviewed stdin-only harness.");
    return;
}

var enrollment = new Method<RawFrame, Proto.EnrollmentResponse>(
    MethodType.Unary,
    "armada.node.transport.v1alpha1.NodeEnrollment",
    "Enroll",
    RawFrame.Marshaller,
    Marshallers.Create(
        static (response, context) =>
        {
            context.SetPayloadLength(response.CalculateSize());
            context.Complete(response.ToByteArray());
        },
        static context => Proto.EnrollmentResponse.Parser.ParseFrom(context.PayloadAsNewBuffer())));

_ = enrollment;
Console.Error.WriteLine("Refusing direct execution: helper must be launched by the reviewed harness bootstrap.");
Environment.ExitCode = 2;
