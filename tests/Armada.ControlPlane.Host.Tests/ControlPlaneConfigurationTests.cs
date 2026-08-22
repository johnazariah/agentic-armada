using Armada.ControlPlane.Host;
using Microsoft.Extensions.Configuration;

namespace Armada.ControlPlane.Host.Tests;

public sealed class ControlPlaneConfigurationTests
{
    [Fact]
    public void Defaults_fail_closed()
    {
        var failures = ControlPlaneConfiguration.Validate(new());

        Assert.Contains(failures, static failure => failure.Code == "lab-mode-disabled");
        Assert.Contains(failures, static failure => failure.Code == "invalid-postgres-connection");
        Assert.Contains(failures, static failure => failure.Code == "invalid-restore-evidence-reference");
    }

    [Fact]
    public void Explicit_disposable_lab_configuration_is_accepted()
    {
        var failures = ControlPlaneConfiguration.Validate(ValidOptions());

        Assert.Empty(failures);
    }

    [Fact]
    public void Remote_binding_is_rejected()
    {
        var options = ValidOptions() with
        {
            Binding = new()
            {
                ListenUrl = "http://127.0.0.1:5080",
                PublicBaseUrl = "http://192.0.2.10:5080"
            },
            Storage = new()
            {
                SchemaManagement = StorageManagementMode.OperatorApplied,
                Backup = ValidBackup()
            }
        };

        var failures = ControlPlaneConfiguration.Validate(options);

        Assert.Contains(failures, static failure => failure.Code == "invalid-public-base-url");
    }

    [Fact]
    public void Invalid_database_and_schema_boundaries_are_rejected()
    {
        var options = ValidOptions() with
        {
            Postgres = new() { ConnectionString = "Host=192.0.2.20;Database=armada;Username=armada" },
            Storage = new()
            {
                SchemaManagement = StorageManagementMode.Unspecified,
                Backup = new()
                {
                    RestoreEvidence = new()
                    {
                        ArtifactPath = "relative-evidence.json",
                        ContentDigest = "sha256:not-a-digest"
                    }
                }
            }
        };

        var failures = ControlPlaneConfiguration.Validate(options);

        Assert.Contains(failures, static failure => failure.Code == "invalid-postgres-connection");
        Assert.Contains(failures, static failure => failure.Code == "invalid-schema-management-boundary");
        Assert.Contains(failures, static failure => failure.Code == "invalid-restore-evidence-reference");
    }

    [Fact]
    public void Only_a_loopback_listener_can_be_applied()
    {
        Assert.True(ControlPlaneConfiguration.TryGetLoopbackListenEndpoint(ValidOptions(), out var endpoint));
        Assert.Equal(System.Net.IPAddress.Loopback, endpoint.Address);
        Assert.Equal(5080, endpoint.Port);

        var rejected = ValidOptions() with
        {
            Binding = new()
            {
                ListenUrl = "https://192.0.2.10:5080",
                PublicBaseUrl = "https://192.0.2.10:5080"
            }
        };

        Assert.False(ControlPlaneConfiguration.TryGetLoopbackListenEndpoint(rejected, out _));
    }

    [Fact]
    public void Kestrel_endpoint_and_url_inputs_are_rejected()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["Kestrel:Endpoints:public:Url"] = "http://0.0.0.0:5080",
                    ["urls"] = "http://0.0.0.0:5081"
                })
            .Build();

        var failures = HostBindingConfiguration.Validate(configuration, "http://0.0.0.0:5082");

        Assert.Contains(failures, static failure => failure.Code == "configured-kestrel-endpoint");
        Assert.Contains(failures, static failure => failure.Code == "configured-host-url");
    }

    internal static ControlPlaneOptions ValidOptions() => new()
    {
        Lab = new() { Enabled = true, Topology = ControlPlaneConfiguration.LabTopology },
        Identity = new() { ServiceName = "armada-control-plane-lab", InstanceId = "mac-lab-001" },
        Binding = new()
        {
            ListenUrl = "http://127.0.0.1:5080",
            PublicBaseUrl = "http://127.0.0.1:5080"
        },
        Postgres = new()
        {
            ConnectionString = "Host=127.0.0.1;Port=5432;Database=armada_lab;Username=armada_lab"
        },
        Storage = new()
        {
            SchemaManagement = StorageManagementMode.OperatorApplied,
            Backup = ValidBackup()
        }
    };

    private static BackupPrerequisiteOptions ValidBackup() => new()
    {
        RestoreEvidence = new()
        {
            ArtifactPath = "/tmp/armada-host-test-restore-evidence.json",
            ContentDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    };
}
