using System.Net;
using System.Text.RegularExpressions;

namespace Armada.Lab.Mtls.LiveHarness;

public sealed record LabHarnessOptions(
    string PostgresAdminConnection,
    IPAddress ListenAddress,
    int EnrollmentPort,
    int StreamPort,
    string DatabaseName,
    string EvidenceDirectory)
{
    private static readonly Regex DatabasePattern =
        new("^armada_c2_[a-f0-9]{32}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static LabHarnessOptions Parse(IReadOnlyDictionary<string, string?> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var connection = Required(values, "postgres-admin-connection");
        var address = IPAddress.Parse(Required(values, "listen-ip"));
        var enrollmentPort = ParsePort(Required(values, "enrollment-port"));
        var streamPort = ParsePort(Required(values, "stream-port"));
        var database = Required(values, "database");
        var evidence = Path.GetFullPath(Required(values, "evidence-directory"));

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            throw new ArgumentException("listen-ip must be one exact non-loopback address.");
        }

        if (enrollmentPort == streamPort)
        {
            throw new ArgumentException("enrollment-port and stream-port must differ.");
        }

        if (!DatabasePattern.IsMatch(database) || database is "armada" or "armada_lab")
        {
            throw new ArgumentException("database must be a generated armada_c2_<32 lowercase hex> name.");
        }

        if (!Path.IsPathFullyQualified(evidence))
        {
            throw new ArgumentException("evidence-directory must be absolute.");
        }

        return new(connection, address, enrollmentPort, streamPort, database, evidence);
    }

    private static string Required(IReadOnlyDictionary<string, string?> values, string name) =>
        values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException($"{name} is required.");

    private static int ParsePort(string value) =>
        int.TryParse(value, out var port) && port is > 0 and <= 65535
            ? port
            : throw new ArgumentException("Ports must be between 1 and 65535.");
}

public static class LabHarnessCommandContract
{
    public const string SshHost = "johnaz-phd-wsl";
    public const string WslDotnet = "/home/johnaz/.local/share/dotnet/dotnet";

    public static string PhaseOneBootstrap(string helperDigest) =>
        $"umask 077; test \"$(id -u)\" = \"$(stat -c %u .)\"; test '{helperDigest}' = \"$(sha256sum helper/Armada.Lab.Mtls.WslClient.dll | awk '{{print $1}}')\"; exec {WslDotnet} helper/Armada.Lab.Mtls.WslClient.dll phase-one";

    public static string PhaseTwoBootstrap(string helperDigest) =>
        $"umask 077; test -f device/public-frame.bin; test '{helperDigest}' = \"$(sha256sum helper/Armada.Lab.Mtls.WslClient.dll | awk '{{print $1}}')\"; exec {WslDotnet} helper/Armada.Lab.Mtls.WslClient.dll phase-two --claim-secret-stdin";
}
