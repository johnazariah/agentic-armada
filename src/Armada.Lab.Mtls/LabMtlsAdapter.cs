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

public sealed class LabMtlsAdapterComposition
{
    internal LabMtlsAdapterComposition(
        LabMtlsRuntimeSettings settings,
        LabMtlsAdapterDependencies dependencies)
    {
        Settings = settings;
        Dependencies = dependencies;
    }

    internal LabMtlsRuntimeSettings Settings { get; }

    internal LabMtlsAdapterDependencies Dependencies { get; }

    internal LabNodeEnrollmentGrpcService CreateEnrollmentService() =>
        new(
            Dependencies.EnrollmentState,
            Dependencies.CertificateIssuer,
            Dependencies.Clock,
            Settings.CertificateLifetime);

    internal RawNodeTransportService CreateTransportService() =>
        new(
            Dependencies.Identities,
            Dependencies.ReplayReceipts,
            Dependencies.Clock);
}

public static class LabMtlsAdapter
{
    // This composes only caller-supplied settings and certificate objects; it never reads
    // a CA, creates claims, persists keys, or starts the application.
    public static LabMtlsAdapterComposition Compose(
        WebApplicationBuilder builder,
        LabMtlsRuntimeSettings settings,
        LabMtlsAdapterDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(dependencies);

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
        return new(settings, dependencies);
    }

    // This registers only custom raw-request service definitions. In particular it
    // never calls MapGrpcService<T>, whose generated request marshallers parse before
    // the strict wire validators can see duplicate or unknown fields.
    public static void Map(
        WebApplication application,
        LabMtlsAdapterComposition composition)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentNullException.ThrowIfNull(composition);

        LabMtlsRawGrpcBinding.Map(
            application,
            composition.CreateEnrollmentService(),
            composition.CreateTransportService());
    }
}
