using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Armada.Lab.Mtls;
using Microsoft.Extensions.Configuration;

namespace Armada.Lab.Mtls.Tests;

public sealed class LabMtlsConfigurationTests
{
    [Fact]
    public void Defaults_fail_closed()
    {
        var failures = LabMtlsConfiguration.Validate(
            new(),
            new ConfigurationBuilder().Build(),
            hostUrls: null);

        Assert.Contains(failures, static failure => failure.Code == "lab-mtls-disabled");
    }

    [Fact]
    public void Explicit_non_loopback_code_only_configuration_is_accepted()
    {
        using var certificate = Certificate();
        var failures = LabMtlsConfiguration.Validate(
            ValidSettings(certificate),
            new ConfigurationBuilder().Build(),
            hostUrls: null);

        Assert.Empty(failures);
    }

    [Fact]
    public void Generic_host_configuration_and_shared_or_loopback_ports_are_rejected()
    {
        using var certificate = Certificate();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["urls"] = "https://192.0.2.20:8443",
                ["Kestrel:Endpoints:external:Url"] = "https://192.0.2.20:9443"
            })
            .Build();
        var settings = ValidSettings(certificate) with
        {
            EnrollmentEndpoint = new(IPAddress.Loopback, 8443),
            StreamEndpoint = new(IPAddress.Parse("192.0.2.20"), 8443)
        };

        var failures = LabMtlsConfiguration.Validate(settings, configuration, hostUrls: null);

        Assert.Contains(failures, static failure => failure.Code == "configured-generic-host-binding");
        Assert.Contains(failures, static failure => failure.Code == "configured-kestrel-endpoint");
        Assert.Contains(failures, static failure => failure.Code == "invalid-enrollment-endpoint");
        Assert.Contains(failures, static failure => failure.Code == "non-distinct-listener-ports");
    }

    private static LabMtlsRuntimeSettings ValidSettings(X509Certificate2 certificate) =>
        new()
        {
            Enabled = true,
            EnrollmentEndpoint = new(IPAddress.Parse("192.0.2.20"), 8443),
            StreamEndpoint = new(IPAddress.Parse("192.0.2.20"), 9443),
            ServerCertificate = certificate,
            ClientCertificateValidation = static (_, _, _) => true
        };

    private static X509Certificate2 Certificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=armada-lab", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        return X509CertificateLoader.LoadPkcs12(
            certificate.Export(X509ContentType.Pfx),
            password: null,
            X509KeyStorageFlags.Exportable);
    }
}
