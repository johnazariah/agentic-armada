using System.Collections.Immutable;
using System.Net;
using Armada.Contracts;
using Microsoft.Extensions.Configuration;
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
    public LocalRestoreEvidenceOptions RestoreEvidence { get; init; } = new();
}

public sealed record LocalRestoreEvidenceOptions
{
    public string ArtifactPath { get; init; } = string.Empty;

    public string ContentDigest { get; init; } = string.Empty;
}

public sealed record ControlPlaneConfigurationFailure(string Code, string Message);

public sealed record HostBindingConfigurationFailure(string Code, string Message);

public sealed record LocalRestoreEvidenceReference(string ArtifactPath, Sha256Digest ContentDigest);

public static class ControlPlaneConfiguration
{
    public const string LabTopology = "mac-control-plane-wsl-disposable-node";

    public static ImmutableArray<ControlPlaneConfigurationFailure> Validate(
        ControlPlaneOptions options)
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

        if (!TryGetRestoreEvidenceReference(options.Storage.Backup, out _))
        {
            failures.Add(new("invalid-restore-evidence-reference", "A local restore evidence artifact requires an absolute path and SHA-256 digest."));
        }

        return failures.ToImmutable();
    }

    public static bool TryGetLoopbackListenEndpoint(ControlPlaneOptions options, out IPEndPoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (TryParseLoopbackHttpUrl(options.Binding.ListenUrl, out var uri) &&
            uri is not null &&
            IPAddress.TryParse(uri.Host, out var address))
        {
            endpoint = new(address, uri.Port);
            return true;
        }

        endpoint = default!;
        return false;
    }

    public static bool TryGetRestoreEvidenceReference(
        BackupPrerequisiteOptions backup,
        out LocalRestoreEvidenceReference reference)
    {
        ArgumentNullException.ThrowIfNull(backup);

        if (string.IsNullOrWhiteSpace(backup.RestoreEvidence.ArtifactPath) ||
            !Path.IsPathFullyQualified(backup.RestoreEvidence.ArtifactPath) ||
            Sha256Digest.Parse(backup.RestoreEvidence.ContentDigest) is not Result<Sha256Digest, ContractValidationError>.Success digest)
        {
            reference = default!;
            return false;
        }

        reference = new(Path.GetFullPath(backup.RestoreEvidence.ArtifactPath), digest.Value);
        return true;
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
            IPAddress.TryParse(parsed.Host, out var address) &&
            IPAddress.IsLoopback(address) &&
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

public static class HostBindingConfiguration
{
    public static ImmutableArray<HostBindingConfigurationFailure> Validate(
        IConfiguration configuration,
        string? hostUrls)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var failures = ImmutableArray.CreateBuilder<HostBindingConfigurationFailure>();
        var endpoints = configuration.GetSection("Kestrel:Endpoints");
        if (!string.IsNullOrWhiteSpace(endpoints.Value) || endpoints.GetChildren().Any())
        {
            failures.Add(new(
                "configured-kestrel-endpoint",
                "Kestrel endpoint configuration is prohibited because the lab host configures only its validated loopback listener."));
        }

        if (!string.IsNullOrWhiteSpace(configuration["urls"]) ||
            !string.IsNullOrWhiteSpace(configuration["ASPNETCORE_URLS"]) ||
            !string.IsNullOrWhiteSpace(configuration["DOTNET_URLS"]) ||
            !string.IsNullOrWhiteSpace(hostUrls))
        {
            failures.Add(new(
                "configured-host-url",
                "URL configuration is prohibited because the lab host configures only its validated loopback listener."));
        }

        return failures.ToImmutable();
    }
}
