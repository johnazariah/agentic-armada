using System.Collections.Immutable;
using Grpc.Core;

namespace Armada.Lab.Mtls.WslClient;

// This client-only wire container intentionally does not expose C1 server binding types.
internal sealed record RawFrame(ImmutableArray<byte> Bytes)
{
    public RawFrame(byte[] bytes)
        : this(ImmutableArray.CreateRange(bytes ?? throw new ArgumentNullException(nameof(bytes))))
    {
    }

    public static RawFrame Read(DeserializationContext context) =>
        new(ImmutableArray.CreateRange(context.PayloadAsNewBuffer()));

    public static readonly Marshaller<RawFrame> Marshaller = Marshallers.Create(
        static (frame, context) =>
        {
            context.SetPayloadLength(frame.Bytes.Length);
            context.Complete(frame.Bytes.ToArray());
        },
        Read);
}
