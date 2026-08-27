using System.Net;
using System.Text.RegularExpressions;

namespace Armada.Lab.Mtls.LiveHarness;

public sealed record LabHarnessOptions(
    IPAddress ListenAddress,
    int EnrollmentPort,
    int StreamPort,
    string DatabaseName,
    string EvidenceDirectory,
    string HelperDirectory,
    string HelperManifest,
    Guid NodeUid,
    long IdentityEpoch)
{
    private static readonly Regex DatabasePattern =
        new("^armada_c2_[a-f0-9]{32}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static LabHarnessOptions Parse(IReadOnlyDictionary<string, string?> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.ContainsKey("postgres-admin-connection"))
        {
            throw new ArgumentException("postgres-admin-connection is forbidden; use ARMADA_C2_POSTGRES_ADMIN_CONNECTION only after the execution gate.");
        }

        var address = IPAddress.Parse(Required(values, "listen-ip"));
        var enrollmentPort = ParsePort(Required(values, "enrollment-port"));
        var streamPort = ParsePort(Required(values, "stream-port"));
        var database = Required(values, "database");
        var evidenceInput = Required(values, "evidence-directory");
        var helperInput = Required(values, "helper-directory");
        var manifestInput = Required(values, "helper-manifest");
        var nodeUid = Guid.TryParseExact(Required(values, "node-uid"), "D", out var parsedNodeUid) && parsedNodeUid != Guid.Empty
            ? parsedNodeUid
            : throw new ArgumentException("node-uid must be a non-empty canonical UUID.");
        var identityEpoch = long.TryParse(Required(values, "identity-epoch"), out var parsedEpoch) && parsedEpoch > 0
            ? parsedEpoch
            : throw new ArgumentException("identity-epoch must be positive.");
        var evidence = Path.GetFullPath(evidenceInput);
        var helper = Path.GetFullPath(helperInput);
        var manifest = Path.GetFullPath(manifestInput);

        if (!Path.IsPathFullyQualified(evidenceInput))
        {
            throw new ArgumentException("evidence-directory must be absolute.");
        }
        if (!Path.IsPathFullyQualified(helperInput) || !Directory.Exists(helper) || new DirectoryInfo(helper).LinkTarget is not null)
        {
            throw new ArgumentException("helper-directory must be an existing absolute non-link published helper directory.");
        }
        if (!Path.IsPathFullyQualified(manifestInput) || !File.Exists(manifest) || new FileInfo(manifest).LinkTarget is not null ||
            IsContainedBy(manifest, helper))
        {
            throw new ArgumentException("helper-manifest must be an existing absolute non-link file outside helper-directory.");
        }

        if (!IsExactUnicast(address))
        {
            throw new ArgumentException("listen-ip must be one exact non-loopback unicast address.");
        }

        if (enrollmentPort == streamPort)
        {
            throw new ArgumentException("enrollment-port and stream-port must differ.");
        }

        if (!DatabasePattern.IsMatch(database) || database is "armada" or "armada_lab")
        {
            throw new ArgumentException("database must be a generated armada_c2_<32 lowercase hex> name.");
        }

        return new(address, enrollmentPort, streamPort, database, evidence, helper, manifest, nodeUid, identityEpoch);
    }

    public static bool IsExactUnicast(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            return false;
        }

        if (address.IsIPv6Multicast)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return bytes.Length != 4 || bytes[0] < 224;
    }

    private static string Required(IReadOnlyDictionary<string, string?> values, string name) =>
        values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException($"{name} is required.");

    private static int ParsePort(string value) =>
        int.TryParse(value, out var port) && port is > 0 and <= 65535
            ? port
            : throw new ArgumentException("Ports must be between 1 and 65535.");

    private static bool IsContainedBy(string path, string directory)
    {
        var prefix = directory.EndsWith(Path.DirectorySeparatorChar) ? directory : directory + Path.DirectorySeparatorChar;
        return string.Equals(path, directory, StringComparison.Ordinal) ||
            path.StartsWith(prefix, StringComparison.Ordinal);
    }
}

public static class LabHarnessCommandContract
{
    public const string SshHost = "johnaz-phd-wsl";
    public const string WslDotnet = "/home/johnaz/.local/share/dotnet/dotnet";
    private static readonly Regex HelperDigestPattern =
        new("^[a-f0-9]{64}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex RemoteRootPattern =
        new("^armada-c2-[a-f0-9]{32}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static string PhaseOneBootstrap(string helperDigest, string remoteRoot) =>
        $"set -eu; umask 077; root=\"$HOME/.cache/{ValidateRemoteRoot(remoteRoot)}\"; test ! -L \"$root\"; test \"$(stat -c '%u:%a' \"$root\")\" = \"$(id -u):700\"; test ! -L \"$root/helper\"; test \"$(stat -c '%u:%a' \"$root/helper\")\" = \"$(id -u):700\"; test ! -L \"$root/helper.manifest\"; cd \"$root\"; sha256sum --strict --check helper.manifest; test '{ValidateHelperDigest(helperDigest)}' = \"$(sha256sum \"$root/helper/Armada.Lab.Mtls.WslClient.dll\" | awk '{{print $1}}')\"; exec {WslDotnet} \"$root/helper/Armada.Lab.Mtls.WslClient.dll\" phase-one";

    public static string PhaseTwoBootstrap(string helperDigest, string remoteRoot) =>
        $"set -eu; umask 077; root=\"$HOME/.cache/{ValidateRemoteRoot(remoteRoot)}\"; test ! -L \"$root\"; test \"$(stat -c '%u:%a' \"$root\")\" = \"$(id -u):700\"; test ! -L \"$root/helper\"; test \"$(stat -c '%u:%a' \"$root/helper\")\" = \"$(id -u):700\"; test ! -L \"$root/helper.manifest\"; cd \"$root\"; sha256sum --strict --check helper.manifest; test ! -L \"$root/device\"; test \"$(stat -c '%u:%a' \"$root/device\")\" = \"$(id -u):700\"; test -f \"$root/device/public-frame.bin\"; test '{ValidateHelperDigest(helperDigest)}' = \"$(sha256sum \"$root/helper/Armada.Lab.Mtls.WslClient.dll\" | awk '{{print $1}}')\"; exec {WslDotnet} \"$root/helper/Armada.Lab.Mtls.WslClient.dll\" phase-two";

    private static string ValidateHelperDigest(string helperDigest) =>
        HelperDigestPattern.IsMatch(helperDigest)
            ? helperDigest
            : throw new ArgumentException("helperDigest must be 64 lowercase hexadecimal characters.");

    private static string ValidateRemoteRoot(string remoteRoot) =>
        RemoteRootPattern.IsMatch(remoteRoot)
            ? remoteRoot
            : throw new ArgumentException("remoteRoot must be an allowlisted generated name.");
}
