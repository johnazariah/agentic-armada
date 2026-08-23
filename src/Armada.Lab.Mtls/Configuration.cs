using System.Collections.Immutable;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Configuration;

namespace Armada.Lab.Mtls;

public sealed record LabMtlsEndpoint(IPAddress Address, int Port);

public sealed record LabMtlsRuntimeSettings
{
    public bool Enabled { get; init; }

    public LabMtlsEndpoint EnrollmentEndpoint { get; init; } = new(IPAddress.None, 0);

    public LabMtlsEndpoint StreamEndpoint { get; init; } = new(IPAddress.None, 0);

    public X509Certificate2? ServerCertificate { get; init; }

    public Func<X509Certificate2?, X509Chain?, SslPolicyErrors, bool>? ClientCertificateValidation { get; init; }

    public TimeSpan CertificateLifetime { get; init; } = TimeSpan.FromDays(1);
}

public sealed record LabMtlsConfigurationFailure(string Code, string Message);

public static class LabMtlsConfiguration
{
    public static ImmutableArray<LabMtlsConfigurationFailure> Validate(
        LabMtlsRuntimeSettings settings,
        IConfiguration configuration,
        string? hostUrls)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(configuration);

        var failures = ImmutableArray.CreateBuilder<LabMtlsConfigurationFailure>();
        if (!settings.Enabled)
        {
            failures.Add(new("lab-mtls-disabled", "The lab mTLS adapter is disabled unless explicitly enabled."));
        }

        if (!IsExactNonLoopbackEndpoint(settings.EnrollmentEndpoint))
        {
            failures.Add(new(
                "invalid-enrollment-endpoint",
                "The enrolment listener must use one exact non-loopback IP address and a valid port."));
        }

        if (!IsExactNonLoopbackEndpoint(settings.StreamEndpoint))
        {
            failures.Add(new(
                "invalid-stream-endpoint",
                "The stream listener must use one exact non-loopback IP address and a valid port."));
        }

        if (settings.EnrollmentEndpoint.Port == settings.StreamEndpoint.Port)
        {
            failures.Add(new(
                "non-distinct-listener-ports",
                "The enrolment and mTLS stream listeners must use distinct ports."));
        }

        if (settings.ServerCertificate is not { HasPrivateKey: true })
        {
            failures.Add(new(
                "invalid-server-certificate",
                "A server certificate with its private key must be supplied explicitly at composition time."));
        }

        if (settings.ClientCertificateValidation is null)
        {
            failures.Add(new(
                "missing-client-certificate-validation",
                "The mTLS stream listener requires an explicit client certificate validation policy."));
        }

        if (settings.CertificateLifetime <= TimeSpan.Zero || settings.CertificateLifetime > TimeSpan.FromDays(31))
        {
            failures.Add(new(
                "invalid-certificate-lifetime",
                "Issued lab certificates must have a positive lifetime no longer than 31 days."));
        }

        AddGenericHostFailures(configuration, hostUrls, failures);
        return failures.ToImmutable();
    }

    internal static void ComposeKestrel(WebApplicationBuilder builder, LabMtlsRuntimeSettings settings)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(settings);

        builder.WebHost.UseKestrel();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            ConfigureTlsEndpoint(kestrel, settings.EnrollmentEndpoint, settings.ServerCertificate!, false, null);
            ConfigureTlsEndpoint(
                kestrel,
                settings.StreamEndpoint,
                settings.ServerCertificate!,
                true,
                settings.ClientCertificateValidation);
        });
    }

    private static bool IsExactNonLoopbackEndpoint(LabMtlsEndpoint endpoint) =>
        endpoint is not null &&
        endpoint.Port is > 0 and <= 65535 &&
        endpoint.Address is not null &&
        endpoint.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6 &&
        !IPAddress.IsLoopback(endpoint.Address) &&
        !IPAddress.Any.Equals(endpoint.Address) &&
        !IPAddress.IPv6Any.Equals(endpoint.Address);

    private static void ConfigureTlsEndpoint(
        KestrelServerOptions kestrel,
        LabMtlsEndpoint endpoint,
        X509Certificate2 certificate,
        bool requireClientCertificate,
        Func<X509Certificate2?, X509Chain?, SslPolicyErrors, bool>? clientCertificateValidation)
    {
        kestrel.Listen(endpoint.Address, endpoint.Port, listen =>
        {
            listen.Protocols = HttpProtocols.Http2;
            listen.UseHttps(new HttpsConnectionAdapterOptions
            {
                ServerCertificate = certificate,
                ClientCertificateMode = requireClientCertificate
                    ? ClientCertificateMode.RequireCertificate
                    : ClientCertificateMode.NoCertificate,
                ClientCertificateValidation = clientCertificateValidation,
                SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            });
        });
    }

    private static void AddGenericHostFailures(
        IConfiguration configuration,
        string? hostUrls,
        ImmutableArray<LabMtlsConfigurationFailure>.Builder failures)
    {
        var endpoints = configuration.GetSection("Kestrel:Endpoints");
        if (!string.IsNullOrWhiteSpace(endpoints.Value) || endpoints.GetChildren().Any())
        {
            failures.Add(new(
                "configured-kestrel-endpoint",
                "Generic Kestrel endpoint configuration is prohibited; endpoints are composed from explicit lab settings only."));
        }

        if (!string.IsNullOrWhiteSpace(hostUrls) ||
            HasConfiguredValue(configuration, "urls", "ASPNETCORE_URLS", "DOTNET_URLS") ||
            HasConfiguredValue(
                configuration,
                "http_ports",
                "https_ports",
                "ASPNETCORE_HTTP_PORTS",
                "ASPNETCORE_HTTPS_PORTS",
                "DOTNET_HTTP_PORTS",
                "DOTNET_HTTPS_PORTS") ||
            HasEnabledValue(
                configuration,
                "preferHostingUrls",
                "ASPNETCORE_PREFERHOSTINGURLS",
                "DOTNET_PREFERHOSTINGURLS"))
        {
            failures.Add(new(
                "configured-generic-host-binding",
                "Generic host URL, port, and hosting-preference configuration is prohibited for the lab mTLS adapter."));
        }
    }

    private static bool HasConfiguredValue(IConfiguration configuration, params string[] keys) =>
        keys.Any(key => !string.IsNullOrWhiteSpace(configuration[key]));

    private static bool HasEnabledValue(IConfiguration configuration, params string[] keys) =>
        keys.Select(key => configuration[key]).Any(static value =>
            !string.IsNullOrWhiteSpace(value) &&
            (!bool.TryParse(value, out var enabled) || enabled));
}
