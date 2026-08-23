using Armada.Lab.Mtls.LiveHarness;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Armada.Lab.Mtls.Harness.Tests;

public sealed class LabHarnessOptionsTests
{
    [Fact]
    public void Accepts_only_a_generated_disposable_database_and_distinct_lan_ports()
    {
        var options = LabHarnessOptions.Parse(Values());

        Assert.Equal("armada_c2_0123456789abcdef0123456789abcdef", options.DatabaseName);
        Assert.Equal(8443, options.EnrollmentPort);
    }

    [Theory]
    [InlineData("armada")]
    [InlineData("armada_lab")]
    [InlineData("armada_c2_UPPERCASE")]
    public void Rejects_unsafe_database_names(string database)
    {
        var values = Values();
        values["database"] = database;

        Assert.Throws<ArgumentException>(() => LabHarnessOptions.Parse(values));
    }

    [Fact]
    public void Bootstrap_has_no_remote_argument_and_uses_the_fixed_dotnet_path()
    {
        var command = LabHarnessCommandContract.PhaseOneBootstrap(
            new string('a', 64),
            "armada-c2_0123456789abcdef0123456789abcdef".Replace('_', '-'));

        Assert.Contains(LabHarnessCommandContract.WslDotnet, command, StringComparison.Ordinal);
        Assert.DoesNotContain("johnaz-phd-wsl", command, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("relative/evidence")]
    [InlineData(".")]
    public void Rejects_relative_evidence_paths(string evidencePath)
    {
        var values = Values();
        values["evidence-directory"] = evidencePath;

        Assert.Throws<ArgumentException>(() => LabHarnessOptions.Parse(values));
    }

    [Theory]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("ff02::1")]
    public void Rejects_non_unicast_listener_addresses(string address)
    {
        var values = Values();
        values["listen-ip"] = address;

        Assert.Throws<ArgumentException>(() => LabHarnessOptions.Parse(values));
    }

    [Fact]
    public void Bootstrap_rejects_unsafe_shell_tokens()
    {
        Assert.Throws<ArgumentException>(() =>
            LabHarnessCommandContract.PhaseOneBootstrap("'; touch unsafe; #", "armada-c2-0123456789abcdef0123456789abcdef"));
        Assert.Throws<ArgumentException>(() =>
            LabHarnessCommandContract.PhaseTwoBootstrap(new string('a', 64), "../unsafe"));
    }

    [Fact]
    public void Public_device_frame_rejects_a_substituted_key_or_csr()
    {
        var frame = Frame();
        frame.Validate();

        Assert.Throws<ArgumentException>(() =>
            (frame with { CertificateSigningRequest = [9, 5, 6] }).Validate());
    }

    [Fact]
    public void Public_device_frame_rejects_a_csr_for_another_p256_key()
    {
        var frame = Frame();
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var otherCsr = new CertificateRequest("CN=other", other, HashAlgorithmName.SHA256).CreateSigningRequest();

        Assert.Throws<ArgumentException>(() =>
            PublicDeviceFrame.Create(frame.NodeUid, frame.IdentityEpoch, frame.SubjectPublicKeyInfo, otherCsr).Validate());
    }

    [Fact]
    public void Public_device_frame_rejects_an_invalid_spki()
    {
        Assert.Throws<ArgumentException>(() =>
            PublicDeviceFrame.Create(Guid.NewGuid(), 1, [1, 2, 3], [4, 5, 6]).Validate());
    }

    [Fact]
    public void Ssh_invocation_supplies_only_the_fixed_host_and_no_remote_command()
    {
        var invocation = SshInvocation.CreateStdinOnlyInvocation();

        Assert.Equal(["-T", LabHarnessCommandContract.SshHost], invocation.ArgumentList);
        Assert.True(invocation.RedirectStandardInput);
    }

    [Fact]
    public async Task Cleanup_runs_every_step_and_fails_after_an_error()
    {
        var steps = new List<string>();
        var cleanup = new CleanupCoordinator(
        [
            ("server", _ => { steps.Add("server"); return Task.CompletedTask; }),
            ("database", _ => throw new InvalidOperationException("drop failed")),
            ("temporary-root", _ => { steps.Add("temporary-root"); return Task.CompletedTask; })
        ]);

        await Assert.ThrowsAsync<AggregateException>(() => cleanup.CleanupAsync(CancellationToken.None));
        Assert.Equal(["server", "temporary-root"], steps);
    }

    [Fact]
    public void Evidence_rejects_secret_bearing_fields()
    {
        Assert.Throws<ArgumentException>(() =>
            RedactedEvidence.Create([new("claimSecret", "not retained")]));
    }

    private static Dictionary<string, string?> Values() => new(StringComparer.Ordinal)
    {
        ["postgres-admin-connection"] = "Host=localhost;Database=postgres",
        ["listen-ip"] = "192.0.2.20",
        ["enrollment-port"] = "8443",
        ["stream-port"] = "9443",
        ["database"] = "armada_c2_0123456789abcdef0123456789abcdef",
        ["evidence-directory"] = "/tmp/armada-evidence"
    };

    private static PublicDeviceFrame Frame()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = key.ExportSubjectPublicKeyInfo();
        var csr = new CertificateRequest("CN=armada-node", key, HashAlgorithmName.SHA256).CreateSigningRequest();
        return PublicDeviceFrame.Create(Guid.NewGuid(), 1, spki, csr);
    }
}
