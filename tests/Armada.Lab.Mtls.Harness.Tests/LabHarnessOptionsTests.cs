using Armada.Lab.Mtls.LiveHarness;

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
        var command = LabHarnessCommandContract.PhaseOneBootstrap(new string('a', 64));

        Assert.Contains(LabHarnessCommandContract.WslDotnet, command, StringComparison.Ordinal);
        Assert.DoesNotContain("johnaz-phd-wsl", command, StringComparison.Ordinal);
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
}
