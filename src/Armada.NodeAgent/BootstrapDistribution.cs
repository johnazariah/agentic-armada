using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Armada.Contracts;

namespace Armada.NodeAgent;

public sealed record BootstrapFailure(string Code, string Message);

public sealed record BootstrapArtifact(string Path, long Length, string Sha256);

public sealed record BootstrapPackageManifest(
    string SchemaVersion,
    string PackageId,
    string Version,
    string Issuer,
    string KeyId,
    DateTimeOffset CreatedAt,
    ImmutableArray<BootstrapArtifact> Artifacts);

public sealed record BootstrapTrustConfiguration(
    string SchemaVersion,
    string Issuer,
    string KeyId,
    string PublicKeyPem);

public sealed record BootstrapSigner(string Issuer, string KeyId, string PrivateKeyPem);

public sealed record BootstrapInstallState(
    string PackageId,
    string Version,
    string ManifestSha256,
    DateTimeOffset InstalledAt);

public sealed record BootstrapStatus(
    bool IsInstalled,
    bool RootsSecure,
    string? PackageId,
    string? Version,
    string? ManifestSha256);

public sealed record BootstrapInstallOutcome(bool Changed, BootstrapInstallState State);

public sealed record BootstrapFileSystemEntry(string RelativePath, bool IsDirectory, bool IsSymbolicLink);

public interface IBootstrapFileSystem
{
    bool DirectoryExists(string path);
    bool FileExists(string path);
    bool IsSymbolicLink(string path);
    IEnumerable<BootstrapFileSystemEntry> EnumerateTree(string path);
    byte[] ReadAllBytes(string path);
    string ReadAllText(string path);
    void CreateOwnerOnlyDirectory(string path);
    bool IsOwnerOnlyDirectory(string path);
    void CopyFile(string source, string destination);
    void WriteAllBytes(string path, byte[] content);
    void WriteAllTextAtomically(string path, string content);
    void MoveDirectory(string source, string destination);
    void DeleteDirectory(string path);
}

public sealed class PhysicalBootstrapFileSystem : IBootstrapFileSystem
{
    public bool DirectoryExists(string path) => Directory.Exists(path);
    public bool FileExists(string path) => File.Exists(path);

    public bool IsSymbolicLink(string path) =>
        new FileInfo(path).LinkTarget is not null || new DirectoryInfo(path).LinkTarget is not null;

    public IEnumerable<BootstrapFileSystemEntry> EnumerateTree(string path)
    {
        var entries = new List<BootstrapFileSystemEntry>();
        Visit(new DirectoryInfo(path), string.Empty, entries);
        return entries;
    }

    public byte[] ReadAllBytes(string path) => File.ReadAllBytes(path);
    public string ReadAllText(string path) => File.ReadAllText(path, Encoding.UTF8);

    public void CreateOwnerOnlyDirectory(string path)
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            Directory.CreateDirectory(path);
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            return;
        }

        throw new PlatformNotSupportedException("Node bootstrap supports Linux and WSL only.");
    }

    public bool IsOwnerOnlyDirectory(string path)
    {
        if (!Directory.Exists(path) || IsSymbolicLink(path))
        {
            return false;
        }

        if (OperatingSystem.IsLinux())
        {
            return IsOwnerOnlyUnixDirectory(path);
        }
        if (OperatingSystem.IsMacOS())
        {
            return IsOwnerOnlyUnixDirectory(path);
        }

        throw new PlatformNotSupportedException("Node bootstrap supports Linux and WSL only.");
    }

    public void CopyFile(string source, string destination)
    {
        CreateOwnerOnlyDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(source, destination, overwrite: false);
    }

    public void WriteAllBytes(string path, byte[] content)
    {
        CreateOwnerOnlyDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, content);
    }

    public void WriteAllTextAtomically(string path, string content)
    {
        var temporaryPath = $"{path}.tmp-{Guid.NewGuid():N}";
        try
        {
            File.WriteAllText(temporaryPath, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    public void MoveDirectory(string source, string destination) => Directory.Move(source, destination);
    public void DeleteDirectory(string path) => Directory.Delete(path, recursive: true);

    private static void Visit(
        DirectoryInfo directory,
        string relativeDirectory,
        ICollection<BootstrapFileSystemEntry> entries)
    {
        foreach (var entry in directory.EnumerateFileSystemInfos().OrderBy(static entry => entry.Name, StringComparer.Ordinal))
        {
            var relativePath = string.IsNullOrEmpty(relativeDirectory)
                ? entry.Name
                : $"{relativeDirectory}/{entry.Name}";
            var isDirectory = entry is DirectoryInfo;
            var isLink = entry.LinkTarget is not null;
            entries.Add(new(relativePath, isDirectory, isLink));
            if (isDirectory && !isLink)
            {
                Visit((DirectoryInfo)entry, relativePath, entries);
            }
        }
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    private static bool IsOwnerOnlyUnixDirectory(string path)
    {
        var mode = File.GetUnixFileMode(path);
        return (mode & (UnixFileMode.GroupRead |
                        UnixFileMode.GroupWrite |
                        UnixFileMode.GroupExecute |
                        UnixFileMode.OtherRead |
                        UnixFileMode.OtherWrite |
                        UnixFileMode.OtherExecute)) == 0;
    }
}

public static class BootstrapPackageFormat
{
    public const string ManifestSchemaVersion = "armada.node-bootstrap/v1";
    public const string TrustSchemaVersion = "armada.node-bootstrap.trust/v1";
    public const string ManifestFileName = "manifest.json";
    public const string SignatureFileName = "manifest.sig";
    public const string PayloadDirectoryName = "payload";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static Result<BootstrapPackageManifest, BootstrapFailure> CreateManifest(
        string packageId,
        string version,
        string issuer,
        string keyId,
        DateTimeOffset createdAt,
        IEnumerable<BootstrapArtifact> artifacts)
    {
        var values = artifacts.OrderBy(static artifact => artifact.Path, StringComparer.Ordinal).ToImmutableArray();
        return ValidateManifest(new(
            ManifestSchemaVersion,
            packageId,
            version,
            issuer,
            keyId,
            createdAt,
            values)) is Result<bool, BootstrapFailure>.Failure failure
            ? Failure<BootstrapPackageManifest>(failure.Error)
            : Success(new BootstrapPackageManifest(
                ManifestSchemaVersion,
                packageId,
                version,
                issuer,
                keyId,
                createdAt,
                values));
    }

    public static Result<bool, BootstrapFailure> ValidateManifest(BootstrapPackageManifest? manifest)
    {
        if (manifest is null ||
            manifest.SchemaVersion != ManifestSchemaVersion ||
            string.IsNullOrWhiteSpace(manifest.PackageId) ||
            !IsSemanticVersion(manifest.Version) ||
            string.IsNullOrWhiteSpace(manifest.Issuer) ||
            string.IsNullOrWhiteSpace(manifest.KeyId) ||
            manifest.CreatedAt == default ||
            manifest.Artifacts.IsDefaultOrEmpty ||
            manifest.Artifacts.Any(static artifact =>
                string.IsNullOrWhiteSpace(artifact.Path) ||
                !IsPayloadPath(artifact.Path) ||
                artifact.Length < 0 ||
                !IsSha256(artifact.Sha256)) ||
            manifest.Artifacts.Select(static artifact => artifact.Path).Distinct(StringComparer.Ordinal).Count() != manifest.Artifacts.Length ||
            !manifest.Artifacts.SequenceEqual(manifest.Artifacts.OrderBy(static artifact => artifact.Path, StringComparer.Ordinal)))
        {
            return Failure<bool>("invalid-bootstrap-manifest", "The bootstrap manifest is incomplete, malformed, or not sorted.");
        }

        return Success(true);
    }

    public static Result<bool, BootstrapFailure> ValidateTrust(BootstrapTrustConfiguration? trust)
    {
        if (trust is null ||
            trust.SchemaVersion != TrustSchemaVersion ||
            string.IsNullOrWhiteSpace(trust.Issuer) ||
            string.IsNullOrWhiteSpace(trust.KeyId) ||
            string.IsNullOrWhiteSpace(trust.PublicKeyPem))
        {
            return Failure<bool>("invalid-bootstrap-trust", "The trust configuration requires schema, issuer, key ID, and public key.");
        }

        return Success(true);
    }

    public static ImmutableArray<byte> CanonicalBytes(BootstrapPackageManifest manifest)
    {
        var fields = new List<string>
        {
            manifest.SchemaVersion,
            manifest.PackageId,
            manifest.Version,
            manifest.Issuer,
            manifest.KeyId,
            manifest.CreatedAt.ToUniversalTime().ToString("O")
        };
        foreach (var artifact in manifest.Artifacts)
        {
            fields.Add(artifact.Path);
            fields.Add(artifact.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
            fields.Add(artifact.Sha256);
        }

        return Encoding.UTF8.GetBytes(string.Concat(fields.Select(static field => $"{field.Length}:{field};"))).ToImmutableArray();
    }

    public static string Sha256(ReadOnlySpan<byte> bytes) =>
        $"sha256:{Convert.ToHexStringLower(SHA256.HashData(bytes))}";

    public static string SerializeManifest(BootstrapPackageManifest manifest) =>
        JsonSerializer.Serialize(manifest, JsonOptions);

    public static string SerializeTrust(BootstrapTrustConfiguration trust) =>
        JsonSerializer.Serialize(trust, JsonOptions);

    public static Result<BootstrapPackageManifest, BootstrapFailure> DeserializeManifest(string text) =>
        Deserialize<BootstrapPackageManifest>(text, "invalid-bootstrap-manifest") switch
        {
            Result<BootstrapPackageManifest, BootstrapFailure>.Success success =>
                ValidateManifest(success.Value) is Result<bool, BootstrapFailure>.Success
                    ? Success(success.Value)
                    : Failure<BootstrapPackageManifest>(((Result<bool, BootstrapFailure>.Failure)ValidateManifest(success.Value)).Error),
            Result<BootstrapPackageManifest, BootstrapFailure>.Failure failure => Failure<BootstrapPackageManifest>(failure.Error),
            _ => Failure<BootstrapPackageManifest>("invalid-bootstrap-manifest", "The JSON document has an unsupported shape.")
        };

    public static Result<BootstrapTrustConfiguration, BootstrapFailure> DeserializeTrust(string text) =>
        Deserialize<BootstrapTrustConfiguration>(text, "invalid-bootstrap-trust") switch
        {
            Result<BootstrapTrustConfiguration, BootstrapFailure>.Success success =>
                ValidateTrust(success.Value) is Result<bool, BootstrapFailure>.Success
                    ? Success(success.Value)
                    : Failure<BootstrapTrustConfiguration>(((Result<bool, BootstrapFailure>.Failure)ValidateTrust(success.Value)).Error),
            Result<BootstrapTrustConfiguration, BootstrapFailure>.Failure failure => Failure<BootstrapTrustConfiguration>(failure.Error),
            _ => Failure<BootstrapTrustConfiguration>("invalid-bootstrap-trust", "The JSON document has an unsupported shape.")
        };

    private static Result<T, BootstrapFailure> Deserialize<T>(string text, string code)
    {
        try
        {
            var value = JsonSerializer.Deserialize<T>(text, JsonOptions);
            return value is null
                ? Failure<T>(code, "The JSON document is required.")
                : Success(value);
        }
        catch (JsonException)
        {
            return Failure<T>(code, "The JSON document is malformed.");
        }
    }

    private static bool IsSemanticVersion(string? value) =>
        value?.Split('.', StringSplitOptions.None) is [var major, var minor, var patch] &&
        int.TryParse(major, out var parsedMajor) && parsedMajor >= 0 &&
        int.TryParse(minor, out var parsedMinor) && parsedMinor >= 0 &&
        int.TryParse(patch, out var parsedPatch) && parsedPatch >= 0;

    private static bool IsPayloadPath(string path) =>
        path.StartsWith($"{PayloadDirectoryName}/", StringComparison.Ordinal) &&
        path.Split('/', StringSplitOptions.None).All(static segment =>
            !string.IsNullOrWhiteSpace(segment) && segment is not "." and not ".." && !segment.Contains('\\'));

    private static bool IsSha256(string? value) =>
        value is { Length: 71 } &&
        value.StartsWith("sha256:", StringComparison.Ordinal) &&
        value[7..].All(static character => char.IsAsciiHexDigit(character) && !char.IsUpper(character));

    private static Result<T, BootstrapFailure> Success<T>(T value) =>
        new Result<T, BootstrapFailure>.Success(value);

    private static Result<T, BootstrapFailure> Failure<T>(string code, string message) =>
        new Result<T, BootstrapFailure>.Failure(new(code, message));

    private static Result<T, BootstrapFailure> Failure<T>(BootstrapFailure failure) =>
        new Result<T, BootstrapFailure>.Failure(failure);
}

public sealed class BootstrapPackager(IBootstrapFileSystem fileSystem, IClock clock)
{
    public Result<BootstrapPackageManifest, BootstrapFailure> Create(
        string sourceDirectory,
        string outputDirectory,
        BootstrapSigner signer,
        string packageId,
        string version)
    {
        if (!fileSystem.DirectoryExists(sourceDirectory) ||
            fileSystem.IsSymbolicLink(sourceDirectory) ||
            fileSystem.DirectoryExists(outputDirectory) ||
            fileSystem.FileExists(outputDirectory))
        {
            return Failure<BootstrapPackageManifest>("bootstrap-package-path-invalid", "The source must exist and the package output path must not exist.");
        }

        var sourceEntries = fileSystem.EnumerateTree(sourceDirectory).ToArray();
        if (sourceEntries.Length == 0 || sourceEntries.Any(static entry => entry.IsSymbolicLink))
        {
            return Failure<BootstrapPackageManifest>("bootstrap-package-source-invalid", "The package source must contain files and no symbolic links.");
        }

        var artifacts = sourceEntries
            .Where(static entry => !entry.IsDirectory)
            .Select(entry =>
            {
                var bytes = fileSystem.ReadAllBytes(Path.Combine(sourceDirectory, entry.RelativePath.Replace('/', Path.DirectorySeparatorChar)));
                return new BootstrapArtifact(
                    $"{BootstrapPackageFormat.PayloadDirectoryName}/{entry.RelativePath}",
                    bytes.LongLength,
                    BootstrapPackageFormat.Sha256(bytes));
            })
            .OrderBy(static artifact => artifact.Path, StringComparer.Ordinal)
            .ToArray();
        if (artifacts.Any(artifact => ContainsCredentialMarker(fileSystem.ReadAllBytes(
                Path.Combine(sourceDirectory, artifact.Path["payload/".Length..].Replace('/', Path.DirectorySeparatorChar))))))
        {
            return Failure<BootstrapPackageManifest>("bootstrap-credential-marker", "Package payload must not contain GitHub credential markers.");
        }

        var manifest = BootstrapPackageFormat.CreateManifest(
            packageId,
            version,
            signer.Issuer,
            signer.KeyId,
            clock.UtcNow,
            artifacts);
        if (manifest is Result<BootstrapPackageManifest, BootstrapFailure>.Failure manifestFailure)
        {
            return Failure<BootstrapPackageManifest>(manifestFailure.Error);
        }

        try
        {
            var value = ((Result<BootstrapPackageManifest, BootstrapFailure>.Success)manifest).Value;
            using var key = RSA.Create();
            key.ImportFromPem(signer.PrivateKeyPem);
            var signature = key.SignData(
                BootstrapPackageFormat.CanonicalBytes(value).AsSpan(),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);

            fileSystem.CreateOwnerOnlyDirectory(outputDirectory);
            fileSystem.CreateOwnerOnlyDirectory(Path.Combine(outputDirectory, BootstrapPackageFormat.PayloadDirectoryName));
            foreach (var entry in sourceEntries.Where(static entry => entry.IsDirectory))
            {
                fileSystem.CreateOwnerOnlyDirectory(Path.Combine(
                    outputDirectory,
                    BootstrapPackageFormat.PayloadDirectoryName,
                    entry.RelativePath.Replace('/', Path.DirectorySeparatorChar)));
            }
            foreach (var artifact in value.Artifacts)
            {
                var relativePath = artifact.Path["payload/".Length..].Replace('/', Path.DirectorySeparatorChar);
                fileSystem.CopyFile(
                    Path.Combine(sourceDirectory, relativePath),
                    Path.Combine(outputDirectory, artifact.Path.Replace('/', Path.DirectorySeparatorChar)));
            }
            fileSystem.WriteAllTextAtomically(Path.Combine(outputDirectory, BootstrapPackageFormat.ManifestFileName), BootstrapPackageFormat.SerializeManifest(value));
            fileSystem.WriteAllTextAtomically(Path.Combine(outputDirectory, BootstrapPackageFormat.SignatureFileName), Convert.ToBase64String(signature));
            return Success(value);
        }
        catch (CryptographicException)
        {
            return Failure<BootstrapPackageManifest>("bootstrap-signing-failed", "The supplied RSA private key cannot sign this package.");
        }
        catch (IOException)
        {
            return Failure<BootstrapPackageManifest>("bootstrap-package-write-failed", "The package could not be written.");
        }
        catch (UnauthorizedAccessException)
        {
            return Failure<BootstrapPackageManifest>("bootstrap-package-write-failed", "The package path is not writable.");
        }
    }

    private static bool ContainsCredentialMarker(ReadOnlySpan<byte> bytes)
    {
        var text = Encoding.UTF8.GetString(bytes);
        return text.Contains("GITHUB_TOKEN", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("GITHUB_PAT_", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("ghp_", StringComparison.Ordinal) ||
               text.Contains("github_pat_", StringComparison.Ordinal);
    }

    private static Result<T, BootstrapFailure> Success<T>(T value) =>
        new Result<T, BootstrapFailure>.Success(value);

    private static Result<T, BootstrapFailure> Failure<T>(string code, string message) =>
        new Result<T, BootstrapFailure>.Failure(new(code, message));

    private static Result<T, BootstrapFailure> Failure<T>(BootstrapFailure failure) =>
        new Result<T, BootstrapFailure>.Failure(failure);
}

public sealed class BootstrapInstaller(IBootstrapFileSystem fileSystem, IClock clock)
{
    public Result<BootstrapInstallOutcome, BootstrapFailure> Install(
        string packageDirectory,
        BootstrapTrustConfiguration trust,
        string installRoot,
        string stateRoot)
    {
        var verified = VerifyPackage(packageDirectory, trust);
        if (verified is Result<VerifiedBootstrapPackage, BootstrapFailure>.Failure verificationFailure)
        {
            return Failure<BootstrapInstallOutcome>(verificationFailure.Error);
        }

        if (EnsureSecureRoot(installRoot) is Result<bool, BootstrapFailure>.Failure installRootFailure)
        {
            return Failure<BootstrapInstallOutcome>(installRootFailure.Error);
        }
        if (EnsureSecureRoot(stateRoot) is Result<bool, BootstrapFailure>.Failure stateRootFailure)
        {
            return Failure<BootstrapInstallOutcome>(stateRootFailure.Error);
        }

        var package = ((Result<VerifiedBootstrapPackage, BootstrapFailure>.Success)verified).Value;
        var statePath = Path.Combine(stateRoot, "active.json");
        var existing = ReadState(statePath);
        if (existing is Result<BootstrapInstallState, BootstrapFailure>.Failure existingFailure &&
            existingFailure.Error.Code != "bootstrap-state-missing")
        {
            return Failure<BootstrapInstallOutcome>(existingFailure.Error);
        }

        var releasesDirectory = Path.Combine(installRoot, "releases");
        var releaseDirectory = Path.Combine(releasesDirectory, package.ManifestSha256["sha256:".Length..]);
        try
        {
            if (EnsureSecureRoot(releasesDirectory) is Result<bool, BootstrapFailure>.Failure releasesRootFailure)
            {
                return Failure<BootstrapInstallOutcome>(releasesRootFailure.Error);
            }
            if (fileSystem.DirectoryExists(releaseDirectory) && fileSystem.IsSymbolicLink(releaseDirectory))
            {
                return Failure<BootstrapInstallOutcome>("bootstrap-root-insecure", "An installed release must not be a symbolic link.");
            }
            var releaseMatches = fileSystem.DirectoryExists(releaseDirectory) && ReleaseMatches(package, releaseDirectory);
            if (fileSystem.DirectoryExists(releaseDirectory) && !releaseMatches)
            {
                fileSystem.DeleteDirectory(releaseDirectory);
            }
            if (!fileSystem.DirectoryExists(releaseDirectory))
            {
                var stagingDirectory = Path.Combine(installRoot, $".staging-{Guid.NewGuid():N}");
                fileSystem.CreateOwnerOnlyDirectory(stagingDirectory);
                try
                {
                    foreach (var artifact in package.Manifest.Artifacts)
                    {
                        var target = Path.Combine(stagingDirectory, artifact.Path["payload/".Length..].Replace('/', Path.DirectorySeparatorChar));
                        fileSystem.WriteAllBytes(target, package.Payloads[artifact.Path]);
                    }
                    fileSystem.MoveDirectory(stagingDirectory, releaseDirectory);
                }
                finally
                {
                    if (fileSystem.DirectoryExists(stagingDirectory))
                    {
                        fileSystem.DeleteDirectory(stagingDirectory);
                    }
                }
            }
            if (existing is Result<BootstrapInstallState, BootstrapFailure>.Success existingState &&
                existingState.Value.ManifestSha256 == package.ManifestSha256 &&
                releaseMatches)
            {
                return Success(new BootstrapInstallOutcome(false, existingState.Value));
            }

            var next = new BootstrapInstallState(
                package.Manifest.PackageId,
                package.Manifest.Version,
                package.ManifestSha256,
                clock.UtcNow);
            fileSystem.WriteAllTextAtomically(statePath, JsonSerializer.Serialize(next));
            return Success(new BootstrapInstallOutcome(true, next));
        }
        catch (IOException)
        {
            return Failure<BootstrapInstallOutcome>("bootstrap-install-failed", "The verified release could not be installed.");
        }
        catch (UnauthorizedAccessException)
        {
            return Failure<BootstrapInstallOutcome>("bootstrap-install-failed", "The install or state root is not writable.");
        }
    }

    public Result<BootstrapStatus, BootstrapFailure> Status(string installRoot, string stateRoot)
    {
        var rootsSecure = fileSystem.DirectoryExists(installRoot) &&
                          fileSystem.DirectoryExists(stateRoot) &&
                          fileSystem.IsOwnerOnlyDirectory(installRoot) &&
                          fileSystem.IsOwnerOnlyDirectory(stateRoot);
        var state = ReadState(Path.Combine(stateRoot, "active.json"));
        return state switch
        {
            Result<BootstrapInstallState, BootstrapFailure>.Success success => Success(new BootstrapStatus(
                true,
                rootsSecure,
                success.Value.PackageId,
                success.Value.Version,
                success.Value.ManifestSha256)),
            Result<BootstrapInstallState, BootstrapFailure>.Failure { Error.Code: "bootstrap-state-missing" } => Success(new BootstrapStatus(
                false, rootsSecure, null, null, null)),
            Result<BootstrapInstallState, BootstrapFailure>.Failure failure => Failure<BootstrapStatus>(failure.Error),
            _ => Failure<BootstrapStatus>("bootstrap-state-invalid", "The local bootstrap state has an unsupported shape.")
        };
    }

    private Result<VerifiedBootstrapPackage, BootstrapFailure> VerifyPackage(
        string packageDirectory,
        BootstrapTrustConfiguration trust)
    {
        if (BootstrapPackageFormat.ValidateTrust(trust) is Result<bool, BootstrapFailure>.Failure trustFailure)
        {
            return Failure<VerifiedBootstrapPackage>(trustFailure.Error);
        }
        if (!fileSystem.DirectoryExists(packageDirectory) || fileSystem.IsSymbolicLink(packageDirectory))
        {
            return Failure<VerifiedBootstrapPackage>("bootstrap-package-path-invalid", "The package directory must exist and must not be a symbolic link.");
        }

        try
        {
            var entries = fileSystem.EnumerateTree(packageDirectory).ToArray();
            var topLevel = entries.Where(static entry => !entry.RelativePath.Contains('/')).ToArray();
            if (entries.Any(static entry => entry.IsSymbolicLink) ||
                topLevel.Length != 3 ||
                !topLevel.Any(static entry => !entry.IsDirectory && entry.RelativePath == BootstrapPackageFormat.ManifestFileName) ||
                !topLevel.Any(static entry => !entry.IsDirectory && entry.RelativePath == BootstrapPackageFormat.SignatureFileName) ||
                !topLevel.Any(static entry => entry.IsDirectory && entry.RelativePath == BootstrapPackageFormat.PayloadDirectoryName))
            {
                return Failure<VerifiedBootstrapPackage>("bootstrap-package-layout-invalid", "The package layout must contain only manifest.json, manifest.sig, and payload.");
            }

            var manifestResult = BootstrapPackageFormat.DeserializeManifest(
                fileSystem.ReadAllText(Path.Combine(packageDirectory, BootstrapPackageFormat.ManifestFileName)));
            if (manifestResult is Result<BootstrapPackageManifest, BootstrapFailure>.Failure manifestFailure)
            {
                return Failure<VerifiedBootstrapPackage>(manifestFailure.Error);
            }
            var manifest = ((Result<BootstrapPackageManifest, BootstrapFailure>.Success)manifestResult).Value;
            if (manifest.Issuer != trust.Issuer || manifest.KeyId != trust.KeyId)
            {
                return Failure<VerifiedBootstrapPackage>("bootstrap-signer-untrusted", "The package signer does not match the configured issuer and key.");
            }

            var encodedSignature = fileSystem.ReadAllText(Path.Combine(packageDirectory, BootstrapPackageFormat.SignatureFileName)).Trim();
            if (!Convert.TryFromBase64String(encodedSignature, new byte[(encodedSignature.Length * 3 + 3) / 4], out _))
            {
                return Failure<VerifiedBootstrapPackage>("bootstrap-signature-invalid", "The detached signature is not Base64.");
            }
            var signature = Convert.FromBase64String(encodedSignature);
            using var key = RSA.Create();
            key.ImportFromPem(trust.PublicKeyPem);
            if (!key.VerifyData(
                    BootstrapPackageFormat.CanonicalBytes(manifest).AsSpan(),
                    signature,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss))
            {
                return Failure<VerifiedBootstrapPackage>("bootstrap-signature-invalid", "The detached signature does not verify.");
            }

            var expectedPaths = manifest.Artifacts.Select(static artifact => artifact.Path).ToHashSet(StringComparer.Ordinal);
            var actualFiles = entries.Where(static entry => !entry.IsDirectory).Select(static entry => entry.RelativePath).ToHashSet(StringComparer.Ordinal);
            actualFiles.Remove(BootstrapPackageFormat.ManifestFileName);
            actualFiles.Remove(BootstrapPackageFormat.SignatureFileName);
            if (!expectedPaths.SetEquals(actualFiles))
            {
                return Failure<VerifiedBootstrapPackage>("bootstrap-package-artifacts-invalid", "The package payload has missing or extra artifacts.");
            }
            var expectedDirectories = manifest.Artifacts
                .SelectMany(static artifact => ParentDirectories(artifact.Path))
                .Append(BootstrapPackageFormat.PayloadDirectoryName)
                .ToHashSet(StringComparer.Ordinal);
            var actualDirectories = entries.Where(static entry => entry.IsDirectory).Select(static entry => entry.RelativePath).ToHashSet(StringComparer.Ordinal);
            if (!expectedDirectories.SetEquals(actualDirectories))
            {
                return Failure<VerifiedBootstrapPackage>("bootstrap-package-artifacts-invalid", "The package payload has missing or extra directories.");
            }
            var payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (var artifact in manifest.Artifacts)
            {
                var bytes = fileSystem.ReadAllBytes(Path.Combine(packageDirectory, artifact.Path.Replace('/', Path.DirectorySeparatorChar)));
                if (bytes.LongLength != artifact.Length || BootstrapPackageFormat.Sha256(bytes) != artifact.Sha256)
                {
                    return Failure<VerifiedBootstrapPackage>("bootstrap-package-artifacts-invalid", "A package artifact does not match its signed digest.");
                }
                if (ContainsCredentialMarker(bytes))
                {
                    return Failure<VerifiedBootstrapPackage>("bootstrap-credential-marker", "Package payload must not contain GitHub credential markers.");
                }
                payloads.Add(artifact.Path, bytes);
            }

            return Success(new VerifiedBootstrapPackage(
                manifest,
                BootstrapPackageFormat.Sha256(BootstrapPackageFormat.CanonicalBytes(manifest).AsSpan()),
                payloads.ToImmutableDictionary(StringComparer.Ordinal)));
        }
        catch (CryptographicException)
        {
            return Failure<VerifiedBootstrapPackage>("bootstrap-signature-invalid", "The configured public key or detached signature is invalid.");
        }
        catch (IOException)
        {
            return Failure<VerifiedBootstrapPackage>("bootstrap-package-read-failed", "The package could not be read.");
        }
        catch (UnauthorizedAccessException)
        {
            return Failure<VerifiedBootstrapPackage>("bootstrap-package-read-failed", "The package is not readable.");
        }
    }

    private Result<bool, BootstrapFailure> EnsureSecureRoot(string path)
    {
        try
        {
            if (fileSystem.FileExists(path) || (fileSystem.DirectoryExists(path) && fileSystem.IsSymbolicLink(path)))
            {
                return Failure<bool>("bootstrap-root-insecure", "The install and state roots must be directories, never symbolic links.");
            }
            fileSystem.CreateOwnerOnlyDirectory(path);
            return fileSystem.IsOwnerOnlyDirectory(path)
                ? Success(true)
                : Failure<bool>("bootstrap-root-insecure", "The install and state roots must be owner-only.");
        }
        catch (IOException)
        {
            return Failure<bool>("bootstrap-root-insecure", "The install or state root cannot be secured.");
        }
        catch (UnauthorizedAccessException)
        {
            return Failure<bool>("bootstrap-root-insecure", "The install or state root cannot be secured.");
        }
    }

    private bool ReleaseMatches(VerifiedBootstrapPackage package, string releaseDirectory)
    {
        var entries = fileSystem.EnumerateTree(releaseDirectory).ToArray();
        if (entries.Any(static entry => entry.IsSymbolicLink))
        {
            return false;
        }

        var expectedFiles = package.Manifest.Artifacts
            .Select(static artifact => artifact.Path["payload/".Length..])
            .ToHashSet(StringComparer.Ordinal);
        var actualFiles = entries.Where(static entry => !entry.IsDirectory)
            .Select(static entry => entry.RelativePath)
            .ToHashSet(StringComparer.Ordinal);
        if (!expectedFiles.SetEquals(actualFiles))
        {
            return false;
        }

        return package.Manifest.Artifacts.All(artifact =>
        {
            var relativePath = artifact.Path["payload/".Length..];
            var bytes = fileSystem.ReadAllBytes(Path.Combine(releaseDirectory, relativePath.Replace('/', Path.DirectorySeparatorChar)));
            return bytes.LongLength == artifact.Length && BootstrapPackageFormat.Sha256(bytes) == artifact.Sha256;
        });
    }

    private Result<BootstrapInstallState, BootstrapFailure> ReadState(string statePath)
    {
        if (!fileSystem.FileExists(statePath))
        {
            return Failure<BootstrapInstallState>("bootstrap-state-missing", "No local bootstrap state exists.");
        }
        if (fileSystem.IsSymbolicLink(statePath))
        {
            return Failure<BootstrapInstallState>("bootstrap-state-invalid", "The local bootstrap state must not be a symbolic link.");
        }
        try
        {
            var state = JsonSerializer.Deserialize<BootstrapInstallState>(fileSystem.ReadAllText(statePath));
            if (state is null ||
                BootstrapPackageFormat.CreateManifest(
                    state.PackageId,
                    state.Version,
                    "state",
                    "state",
                    state.InstalledAt,
                    [new BootstrapArtifact("payload/state", 0, state.ManifestSha256)]) is not
                    Result<BootstrapPackageManifest, BootstrapFailure>.Success)
            {
                return Failure<BootstrapInstallState>("bootstrap-state-invalid", "The local bootstrap state is malformed.");
            }

            return Success(state);
        }
        catch (JsonException)
        {
            return Failure<BootstrapInstallState>("bootstrap-state-invalid", "The local bootstrap state is malformed.");
        }
        catch (IOException)
        {
            return Failure<BootstrapInstallState>("bootstrap-state-invalid", "The local bootstrap state cannot be read.");
        }
    }

    private static bool ContainsCredentialMarker(ReadOnlySpan<byte> bytes) =>
        Encoding.UTF8.GetString(bytes).Contains("GITHUB_TOKEN", StringComparison.OrdinalIgnoreCase) ||
        Encoding.UTF8.GetString(bytes).Contains("GITHUB_PAT_", StringComparison.OrdinalIgnoreCase) ||
        Encoding.UTF8.GetString(bytes).Contains("ghp_", StringComparison.Ordinal) ||
        Encoding.UTF8.GetString(bytes).Contains("github_pat_", StringComparison.Ordinal);

    private static IEnumerable<string> ParentDirectories(string path)
    {
        var segments = path.Split('/', StringSplitOptions.None);
        for (var count = 1; count < segments.Length; count++)
        {
            yield return string.Join('/', segments[..count]);
        }
    }

    private static Result<T, BootstrapFailure> Success<T>(T value) =>
        new Result<T, BootstrapFailure>.Success(value);

    private static Result<T, BootstrapFailure> Failure<T>(string code, string message) =>
        new Result<T, BootstrapFailure>.Failure(new(code, message));

    private static Result<T, BootstrapFailure> Failure<T>(BootstrapFailure failure) =>
        new Result<T, BootstrapFailure>.Failure(failure);

    private sealed record VerifiedBootstrapPackage(
        BootstrapPackageManifest Manifest,
        string ManifestSha256,
        ImmutableDictionary<string, byte[]> Payloads);
}
