using System.Collections.Immutable;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.Versioning;
using Armada.Application;
using Armada.Contracts;
using Armada.Infrastructure.Postgres;
using Armada.Lab.Mtls;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace Armada.Lab.Mtls.LiveHarness;

[SupportedOSPlatform("macos")]
public sealed class VerifiedTemporaryRoot : IAsyncDisposable
{
    private readonly string path;

    private VerifiedTemporaryRoot(string path) => this.path = path;

    public string Path => path;

    public static VerifiedTemporaryRoot Create()
    {
        EnsureMacOs();
        var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"armada-c2-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var mode = File.GetUnixFileMode(path);
        if (mode != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute) ||
            new DirectoryInfo(path).LinkTarget is not null)
        {
            throw new IOException("The C2 temporary root is not an owner-only non-link directory.");
        }

        return new(path);
    }

    public string CreateDirectory(string name)
    {
        EnsureMacOs();
        if (name.IndexOfAny(['/', '\\', '\0']) >= 0)
        {
            throw new ArgumentException("Temporary child names must be a single path segment.", nameof(name));
        }

        var child = System.IO.Path.Combine(path, name);
        Directory.CreateDirectory(child, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        if (File.GetUnixFileMode(child) != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute) ||
            new DirectoryInfo(child).LinkTarget is not null)
        {
            throw new IOException("The C2 temporary child is not owner-only.");
        }

        return child;
    }

    public ValueTask DisposeAsync()
    {
        EnsureMacOs();
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    private static void EnsureMacOs()
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("The C2 live harness supports macOS only.");
        }
    }
}

[SupportedOSPlatform("macos")]
public sealed class LiveHarnessExecution
{
    // This method is reachable only from Program's two-factor execution branch.
    public async Task RunAsync(
        LabHarnessOptions options,
        Func<CancellationToken, Task<PublicDeviceFrame>> phaseOne,
        Func<PublicDeviceFrame, ReadOnlyMemory<byte>, X509Certificate2, CancellationToken, Task<IReadOnlyList<EvidenceItem>>> phaseTwo,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(phaseOne);
        ArgumentNullException.ThrowIfNull(phaseTwo);

        var frame = await phaseOne(cancellationToken);
        frame.Validate();
        var digest = Sha256Digest.Parse($"sha256:{Convert.ToHexString(frame.PublicKeySha256).ToLowerInvariant()}");
        if (digest is Result<Sha256Digest, ContractValidationError>.Failure)
        {
            throw new InvalidOperationException("Validated device digest was not canonical.");
        }

        await using var root = VerifiedTemporaryRoot.Create();
        using var authority = new EphemeralLabAuthority(options.ListenAddress, TimeSpan.FromHours(1));
        await using var database = new DisposablePostgresDatabase(options.PostgresAdminConnection, options.DatabaseName);
        var secret = RandomNumberGenerator.GetBytes(NodeTransportProtocol.MinimumClaimSecretBytes);
        WebApplication? application = null;
        try
        {
            await database.CreateAndMigrateAsync(cancellationToken);
            var claim = new EnrollmentClaimReference(
                Guid.NewGuid(),
                new NodeUid(frame.NodeUid),
                frame.IdentityEpoch,
                ((Result<Sha256Digest, ContractValidationError>.Success)digest).Value);
            await database.SeedClaimAsync(claim, secret, DateTimeOffset.UtcNow.AddMinutes(10), cancellationToken);
            application = BuildServer(options, database.DataSource, authority);
            await application.StartAsync(cancellationToken);
            await WriteEvidenceAsync(
                options.EvidenceDirectory,
                await phaseTwo(frame, secret, authority.CaCertificate, cancellationToken),
                cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            if (application is not null)
            {
                await application.DisposeAsync();
            }
        }
    }

    private static WebApplication BuildServer(
        LabHarnessOptions options,
        Npgsql.NpgsqlDataSource dataSource,
        EphemeralLabAuthority authority)
    {
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        var repository = new PostgresNodeEnrollmentStateRepository(dataSource);
        var settings = new LabMtlsRuntimeSettings
        {
            Enabled = true,
            EnrollmentEndpoint = new(options.ListenAddress, options.EnrollmentPort),
            StreamEndpoint = new(options.ListenAddress, options.StreamPort),
            ServerCertificate = authority.ServerCertificate,
            CertificateLifetime = TimeSpan.FromHours(1),
            ClientCertificateValidation = (certificate, _, errors) =>
                certificate is not null &&
                errors == SslPolicyErrors.None &&
                certificate.Verify()
        };
        var composition = LabMtlsAdapter.Compose(
            builder,
            settings,
            new(
                new ControllerEnrollmentStateService(repository, repository),
                authority,
                repository,
                repository));
        var application = builder.Build();
        LabMtlsAdapter.Map(application, composition);
        return application;
    }

    private static async Task WriteEvidenceAsync(
        string directory,
        IReadOnlyList<EvidenceItem> items,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("The C2 live harness supports macOS only.");
        }

        var evidence = RedactedEvidence.Create(items);
        Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var path = System.IO.Path.Combine(directory, "c2-evidence.txt");
        await File.WriteAllLinesAsync(path, evidence.Select(item => $"{item.Name}={item.Value}"), cancellationToken);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
