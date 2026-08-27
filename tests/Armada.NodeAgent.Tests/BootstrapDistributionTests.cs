using System.Security.Cryptography;
using Armada.Contracts;
using Armada.NodeAgent;

namespace Armada.NodeAgent.Tests;

public sealed class BootstrapDistributionTests
{
    [Fact]
    public void Installer_rejects_tampered_missing_extra_and_symbolic_link_artifacts()
    {
        using var tampered = new BootstrapFixture();
        var tamperedPackage = tampered.CreatePackage("1.0.0");
        File.AppendAllText(Path.Combine(tamperedPackage, "payload", "agent"), "changed");

        using var missing = new BootstrapFixture();
        var missingPackage = missing.CreatePackage("1.0.0");
        File.Delete(Path.Combine(missingPackage, "payload", "agent"));

        using var extra = new BootstrapFixture();
        var extraPackage = extra.CreatePackage("1.0.0");
        File.WriteAllText(Path.Combine(extraPackage, "payload", "unexpected"), "extra");

        using var linked = new BootstrapFixture();
        var linkedPackage = linked.CreatePackage("1.0.0");
        var agent = Path.Combine(linkedPackage, "payload", "agent");
        File.Delete(agent);
        File.CreateSymbolicLink(agent, Path.Combine(linked.Root, "outside"));

        Assert.Equal("bootstrap-package-artifacts-invalid", Failure(tampered.Install(tamperedPackage)).Code);
        Assert.Equal("bootstrap-package-artifacts-invalid", Failure(missing.Install(missingPackage)).Code);
        Assert.Equal("bootstrap-package-artifacts-invalid", Failure(extra.Install(extraPackage)).Code);
        Assert.Equal("bootstrap-package-layout-invalid", Failure(linked.Install(linkedPackage)).Code);
    }

    [Fact]
    public void Installer_rejects_a_valid_package_when_the_configured_signer_is_untrusted()
    {
        using var fixture = new BootstrapFixture();
        var package = fixture.CreatePackage("1.0.0");
        using var untrusted = RSA.Create(2048);
        var trust = fixture.Trust with { KeyId = "untrusted", PublicKeyPem = untrusted.ExportRSAPublicKeyPem() };

        var result = fixture.Installer.Install(package, trust, fixture.InstallRoot, fixture.StateRoot);

        Assert.Equal("bootstrap-signer-untrusted", Failure(result).Code);
    }

    [Fact]
    public void Installer_is_idempotent_upgrades_a_new_verified_digest_and_reports_local_status()
    {
        using var fixture = new BootstrapFixture();
        var firstPackage = fixture.CreatePackage("1.0.0");

        var first = Success(fixture.Install(firstPackage));
        var repeated = Success(fixture.Install(firstPackage));
        File.WriteAllText(Path.Combine(fixture.SourceRoot, "agent"), "agent-v2");
        var secondPackage = fixture.CreatePackage("1.1.0");
        var upgraded = Success(fixture.Install(secondPackage));
        var status = Success(fixture.Installer.Status(fixture.InstallRoot, fixture.StateRoot));

        Assert.True(first.Changed);
        Assert.False(repeated.Changed);
        Assert.True(upgraded.Changed);
        Assert.NotEqual(first.State.ManifestSha256, upgraded.State.ManifestSha256);
        Assert.True(status.IsInstalled);
        Assert.True(status.RootsSecure);
        Assert.Equal("1.1.0", status.Version);
        Assert.Equal(upgraded.State.ManifestSha256, status.ManifestSha256);
    }

    [Fact]
    public void Installer_replaces_a_tampered_existing_digest_named_release()
    {
        using var fixture = new BootstrapFixture();
        var package = fixture.CreatePackage("1.0.0");
        var first = Success(fixture.Install(package));
        var release = Path.Combine(
            fixture.InstallRoot,
            "releases",
            first.State.ManifestSha256["sha256:".Length..],
            "agent");
        File.WriteAllText(release, "tampered");

        var reconciled = Success(fixture.Install(package));

        Assert.True(reconciled.Changed);
        Assert.Equal("agent-v1", File.ReadAllText(release));
    }

    [Fact]
    public void Packager_rejects_credentials_and_clean_artifacts_contain_no_github_credential_markers()
    {
        using var fixture = new BootstrapFixture();
        File.WriteAllText(Path.Combine(fixture.SourceRoot, "credentials"), "GITHUB_TOKEN=not-a-secret");

        var rejected = fixture.Packager.Create(
            fixture.SourceRoot,
            Path.Combine(fixture.Root, "credential-package"),
            fixture.Signer,
            "node-agent",
            "1.0.0");
        File.Delete(Path.Combine(fixture.SourceRoot, "credentials"));
        var package = fixture.CreatePackage("1.0.0");
        var payload = Directory.EnumerateFiles(Path.Combine(package, "payload"), "*", SearchOption.AllDirectories)
            .Select(File.ReadAllText);

        Assert.Equal("bootstrap-credential-marker", Failure(rejected).Code);
        Assert.DoesNotContain(payload, static content =>
            content.Contains("GITHUB_TOKEN", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("ghp_", StringComparison.Ordinal) ||
            content.Contains("github_pat_", StringComparison.Ordinal));
    }

    [Fact]
    public void Format_validation_rejects_malformed_input_and_status_reports_an_absent_installation()
    {
        using var fixture = new BootstrapFixture();
        var manifest = Success(fixture.Packager.Create(
            fixture.SourceRoot,
            Path.Combine(fixture.Root, "format-package"),
            fixture.Signer,
            "node-agent",
            "1.0.0"));
        var trust = fixture.Trust;

        var status = Success(fixture.Installer.Status(fixture.InstallRoot, fixture.StateRoot));

        Assert.False(status.IsInstalled);
        Assert.False(status.RootsSecure);
        Assert.IsType<Result<BootstrapPackageManifest, BootstrapFailure>.Success>(
            BootstrapPackageFormat.DeserializeManifest(BootstrapPackageFormat.SerializeManifest(manifest)));
        Assert.IsType<Result<BootstrapTrustConfiguration, BootstrapFailure>.Success>(
            BootstrapPackageFormat.DeserializeTrust(BootstrapPackageFormat.SerializeTrust(trust)));
        Assert.Equal("invalid-bootstrap-manifest", Failure(BootstrapPackageFormat.DeserializeManifest("{")).Code);
        Assert.Equal("invalid-bootstrap-trust", Failure(BootstrapPackageFormat.ValidateTrust(null)).Code);
        Assert.Equal("invalid-bootstrap-manifest", Failure(BootstrapPackageFormat.ValidateManifest(null)).Code);
    }

    private static T Success<T>(Result<T, BootstrapFailure> result) =>
        result is Result<T, BootstrapFailure>.Success success
            ? success.Value
            : throw new Xunit.Sdk.XunitException($"Expected success but got {Failure(result).Code}.");

    private static BootstrapFailure Failure<T>(Result<T, BootstrapFailure> result) =>
        result is Result<T, BootstrapFailure>.Failure failure
            ? failure.Error
            : throw new Xunit.Sdk.XunitException("Expected failure.");

    private sealed class BootstrapFixture : IDisposable
    {
        private readonly RSA signingKey = RSA.Create(2048);

        public BootstrapFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), $"armada-bootstrap-{Guid.NewGuid():N}");
            SourceRoot = Path.Combine(Root, "source");
            InstallRoot = Path.Combine(Root, "install");
            StateRoot = Path.Combine(Root, "state");
            Directory.CreateDirectory(SourceRoot);
            File.WriteAllText(Path.Combine(SourceRoot, "agent"), "agent-v1");
            Packager = new BootstrapPackager(new PhysicalBootstrapFileSystem(), new FixedClock(Now));
            Installer = new BootstrapInstaller(new PhysicalBootstrapFileSystem(), new FixedClock(Now));
        }

        public static DateTimeOffset Now { get; } = new(2026, 8, 27, 10, 0, 0, TimeSpan.Zero);
        public string Root { get; }
        public string SourceRoot { get; }
        public string InstallRoot { get; }
        public string StateRoot { get; }
        public BootstrapPackager Packager { get; }
        public BootstrapInstaller Installer { get; }
        public BootstrapSigner Signer => new("armada-release", "test-key", signingKey.ExportRSAPrivateKeyPem());
        public BootstrapTrustConfiguration Trust => new(
            BootstrapPackageFormat.TrustSchemaVersion,
            "armada-release",
            "test-key",
            signingKey.ExportRSAPublicKeyPem());

        public string CreatePackage(string version)
        {
            var package = Path.Combine(Root, $"package-{version}");
            _ = Success(Packager.Create(SourceRoot, package, Signer, "node-agent", version));
            return package;
        }

        public Result<BootstrapInstallOutcome, BootstrapFailure> Install(string package) =>
            Installer.Install(package, Trust, InstallRoot, StateRoot);

        public void Dispose()
        {
            signingKey.Dispose();
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }
}
