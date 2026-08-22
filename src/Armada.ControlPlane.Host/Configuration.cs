using System.Collections.Immutable;
using System.Net;
using Npgsql;

namespace Armada.ControlPlane.Host;

public sealed record ControlPlaneOptions
{
    public const string SectionName = "ControlPlane";

    public LabModeOptions Lab { get; init; } = new();

    public ControlPlaneIdentityOptions Identity { get; init; } = new();

    public ControlPlaneBindingOptions Binding { get; init; } = new();

    public PostgresOptions Postgres { get; init; } = new();

    public StorageOptions Storage { get; init; } = new();
}

public sealed record LabModeOptions
{
    public bool Enabled { get; init; }

    public string Topology { get; init; } = string.Empty;
}

public sealed record ControlPlaneIdentityOptions
{
    public string ServiceName { get; init; } = string.Empty;

    public string InstanceId { get; init; } = string.Empty;
}

public sealed record ControlPlaneBindingOptions
{
    public string ListenUrl { get; init; } = string.Empty;

    public string PublicBaseUrl { get; init; } = string.Empty;
}

public sealed record PostgresOptions
{
    public string ConnectionString { get; init; } = string.Empty;
}

public enum StorageManagementMode
{
    Unspecified,
    OperatorApplied
}

public sealed record StorageOptions
{
    public StorageManagementMode SchemaManagement { get; init; }

    public BackupPrerequisiteOptions Backup { get; init; } = new();
}

public sealed record BackupPrerequisiteOptions
{
    public string RestoreEvidenceReference { get; init; } = string.Empty;

    public DateTimeOffset? LastRestoreVerifiedAtUtc { get; init; }

    public int MaximumEvidenceAgeDays { get; init; } = 30;
}

public sealed record ControlPlaneConfigurationFailure(string Code, string Message);

public static class ControlPlaneConfiguration
{
    public const string LabTopology = "mac-control-plane-wsl-disposable-node";

    public static ImmutableArray<ControlPlaneConfigurationFailure> Validate(
        ControlPlaneOptions options,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(options);

        var failures = ImmutableArray.CreateBuilder<ControlPlaneConfigurationFailure>();

        if (!options.Lab.Enabled)
        {
            failures.Add(new("lab-mode-disabled", "This host is lab-only and requires explicit lab mode."));
        }

        if (!string.Equals(options.Lab.Topology, LabTopology, StringComparison.Ordinal))
        {
            failures.Add(new("invalid-lab-topology", "The configured topology is not the approved disposable lab topology."));
        }

        if (!IsSafeIdentifier(options.Identity.ServiceName) || !IsSafeIdentifier(options.Identity.InstanceId))
        {
            failures.Add(new("invalid-control-plane-identity", "Service name and instance ID must be stable safe identifiers."));
        }

        if (!TryParseLoopbackHttpUrl(options.Binding.ListenUrl, out var listenUri))
        {
            failures.Add(new("invalid-listen-url", "The lab host must bind to a loopback HTTP URL without a path."));
        }

        if (!TryParseLoopbackHttpUrl(options.Binding.PublicBaseUrl, out var publicUri) ||
            listenUri is null ||
            publicUri is null ||
            Uri.Compare(listenUri, publicUri, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) != 0)
        {
            failures.Add(new("invalid-public-base-url", "The lab public base URL must be the same loopback origin as the listener."));
        }

        if (!IsValidPostgresConfiguration(options.Postgres.ConnectionString))
        {
            failures.Add(new("invalid-postgres-connection", "PostgreSQL must be explicitly configured for a local lab database."));
        }

        if (options.Storage.SchemaManagement != StorageManagementMode.OperatorApplied)
        {
            failures.Add(new("invalid-schema-management-boundary", "Schema changes must remain operator-applied in the lab baseline."));
        }

        ValidateBackupPrerequisites(options.Storage.Backup, now, failures);
        return failures.ToImmutable();
    }

    public static bool TryGetLoopbackListenUrl(ControlPlaneOptions options, out string listenUrl)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (TryParseLoopbackHttpUrl(options.Binding.ListenUrl, out var uri) && uri is not null)
        {
            listenUrl = uri.AbsoluteUri;
            return true;
        }

        listenUrl = string.Empty;
        return false;
    }

    private static void ValidateBackupPrerequisites(
        BackupPrerequisiteOptions backup,
        DateTimeOffset now,
        ImmutableArray<ControlPlaneConfigurationFailure>.Builder failures)
    {
        if (string.IsNullOrWhiteSpace(backup.RestoreEvidenceReference))
        {
            failures.Add(new("missing-restore-evidence-reference", "A durable restore-drill evidence reference is required before readiness."));
        }

        if (backup.MaximumEvidenceAgeDays is < 1 or > 90)
        {
            failures.Add(new("invalid-restore-evidence-age", "Restore-drill evidence must have a maximum age between one and ninety days."));
        }

        if (backup.LastRestoreVerifiedAtUtc is null ||
            backup.LastRestoreVerifiedAtUtc > now ||
            (backup.MaximumEvidenceAgeDays is >= 1 and <= 90 &&
             now - backup.LastRestoreVerifiedAtUtc > TimeSpan.FromDays(backup.MaximumEvidenceAgeDays)))
        {
            failures.Add(new("stale-restore-evidence", "A current restore-drill verification is required before readiness."));
        }
    }

    private static bool IsValidPostgresConfiguration(string connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            return false;
        }

        try
        {
            var builder = new NpgsqlConnectionStringBuilder(connectionString);
            return !string.IsNullOrWhiteSpace(builder.Database) &&
                   !string.IsNullOrWhiteSpace(builder.Username) &&
                   IsLoopbackHost(builder.Host ?? string.Empty);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool IsSafeIdentifier(string value) =>
        value.Length is >= 3 and <= 63 &&
        value.All(static character =>
            character is >= 'a' and <= 'z' ||
            character is >= '0' and <= '9' ||
            character == '-');

    private static bool TryParseLoopbackHttpUrl(string value, out Uri? uri)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var parsed) &&
            parsed.Scheme == Uri.UriSchemeHttp &&
            parsed.IsLoopback &&
            parsed.AbsolutePath == "/" &&
            string.IsNullOrEmpty(parsed.Query) &&
            string.IsNullOrEmpty(parsed.Fragment))
        {
            uri = parsed;
            return true;
        }

        uri = null;
        return false;
    }

    private static bool IsLoopbackHost(string value) =>
        string.Equals(value, "localhost", StringComparison.OrdinalIgnoreCase) ||
        (IPAddress.TryParse(value, out var address) && IPAddress.IsLoopback(address));
}
