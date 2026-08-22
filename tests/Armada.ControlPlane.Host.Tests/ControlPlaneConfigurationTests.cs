using Armada.ControlPlane.Host;

namespace Armada.ControlPlane.Host.Tests;

public sealed class ControlPlaneConfigurationTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 23, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Defaults_fail_closed()
    {
        var failures = ControlPlaneConfiguration.Validate(new(), Now);

        Assert.Contains(failures, static failure => failure.Code == "lab-mode-disabled");
        Assert.Contains(failures, static failure => failure.Code == "invalid-postgres-connection");
        Assert.Contains(failures, static failure => failure.Code == "missing-restore-evidence-reference");
    }

    [Fact]
    public void Explicit_disposable_lab_configuration_is_accepted()
    {
        var failures = ControlPlaneConfiguration.Validate(ValidOptions(), Now);

        Assert.Empty(failures);
    }

    [Fact]
    public void Remote_binding_and_stale_backup_evidence_are_rejected()
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
                Backup = new()
                {
                    RestoreEvidenceReference = "lab://restore-drill/001",
                    LastRestoreVerifiedAtUtc = Now.AddDays(-31),
                    MaximumEvidenceAgeDays = 30
                }
            }
        };

        var failures = ControlPlaneConfiguration.Validate(options, Now);

        Assert.Contains(failures, static failure => failure.Code == "invalid-public-base-url");
        Assert.Contains(failures, static failure => failure.Code == "stale-restore-evidence");
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
                    RestoreEvidenceReference = "lab://restore-drill/001",
                    LastRestoreVerifiedAtUtc = Now.AddDays(-1),
                    MaximumEvidenceAgeDays = 0
                }
            }
        };

        var failures = ControlPlaneConfiguration.Validate(options, Now);

        Assert.Contains(failures, static failure => failure.Code == "invalid-postgres-connection");
        Assert.Contains(failures, static failure => failure.Code == "invalid-schema-management-boundary");
        Assert.Contains(failures, static failure => failure.Code == "invalid-restore-evidence-age");
    }

    [Fact]
    public void Only_a_loopback_listener_can_be_applied()
    {
        Assert.True(ControlPlaneConfiguration.TryGetLoopbackListenUrl(ValidOptions(), out var listenUrl));
        Assert.Equal("http://127.0.0.1:5080/", listenUrl);

        var rejected = ValidOptions() with
        {
            Binding = new()
            {
                ListenUrl = "https://192.0.2.10:5080",
                PublicBaseUrl = "https://192.0.2.10:5080"
            }
        };

        Assert.False(ControlPlaneConfiguration.TryGetLoopbackListenUrl(rejected, out _));
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
            Backup = new()
            {
                RestoreEvidenceReference = "lab://restore-drill/001",
                LastRestoreVerifiedAtUtc = Now.AddDays(-1),
                MaximumEvidenceAgeDays = 30
            }
        }
    };
}
