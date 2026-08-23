using Armada.Application;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Armada.Lab.Mtls;

public sealed record LabMtlsAdapterDependencies(
    ControllerEnrollmentStateService EnrollmentState,
    ILabCertificateIssuer CertificateIssuer,
    INodeIdentityRegistry Identities,
    ITransportReplayReceiptStore ReplayReceipts,
    TimeProvider? Clock = null);

public sealed class RawStreamProtobufUnavailableException : InvalidOperationException
{
    public RawStreamProtobufUnavailableException()
        : base(
            "The lab mTLS adapter is blocked: ASP.NET Core's generated gRPC stream binder supplies deserialised " +
            "NodeToControl messages rather than their received protobuf bytes. Re-serialising would weaken replay " +
            "validation, so no stream listener is exposed until a byte-preserving gRPC binding is available.")
    {
    }
}

public static class LabMtlsAdapter
{
    // This composes only caller-supplied settings and certificate objects; it never reads
    // a CA, creates claims, persists keys, or starts the application.
    public static void Compose(
        WebApplicationBuilder builder,
        LabMtlsRuntimeSettings settings,
        LabMtlsAdapterDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(dependencies);

        if (!settings.Enabled)
        {
            return;
        }

        var failures = LabMtlsConfiguration.Validate(
            settings,
            builder.Configuration,
            builder.WebHost.GetSetting(WebHostDefaults.ServerUrlsKey));
        if (!failures.IsEmpty)
        {
            throw new InvalidOperationException(string.Join(" ", failures.Select(static failure => failure.Message)));
        }

        LabMtlsConfiguration.ComposeKestrel(builder, settings);
        builder.Services.AddGrpc();
        builder.Services.AddSingleton(new LabNodeEnrollmentGrpcService(
            dependencies.EnrollmentState,
            dependencies.CertificateIssuer,
            dependencies.Clock,
            settings.CertificateLifetime));
        builder.Services.AddSingleton(new RawNodeTransportService(
            dependencies.Identities,
            dependencies.ReplayReceipts,
            dependencies.Clock));

    }

    // This registers only custom raw-request service definitions. In particular it
    // never calls MapGrpcService<T>, whose generated request marshallers parse before
    // the strict wire validators can see duplicate or unknown fields.
    public static void Map(
        WebApplication application,
        LabMtlsAdapterDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentNullException.ThrowIfNull(dependencies);

        LabMtlsRawGrpcBinding.Map(
            application,
            new LabNodeEnrollmentGrpcService(
                dependencies.EnrollmentState,
                dependencies.CertificateIssuer,
                dependencies.Clock),
            new RawNodeTransportService(
                dependencies.Identities,
                dependencies.ReplayReceipts,
                dependencies.Clock));
    }
}
