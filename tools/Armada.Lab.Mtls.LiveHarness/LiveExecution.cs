using System.Collections.Immutable;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.Versioning;
using System.Runtime.ExceptionServices;
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
            var directory = new DirectoryInfo(path);
            if (directory.LinkTarget is not null)
            {
                throw new IOException("Refusing to delete a substituted symbolic link.");
            }

            // This root intentionally contains no persisted material. Refuse rather than
            // recursively walking a tree that could have been replaced after verification.
            directory.Delete(recursive: false);
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
        Func<EnrollmentClaimReference, INodeIdentityRegistry, PublicDeviceFrame, ReadOnlyMemory<byte>, X509Certificate2, CancellationToken, Task<IReadOnlyList<EvidenceItem>>> phaseTwo,
        Func<CancellationToken, Task> cleanupRemote,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(phaseOne);
        ArgumentNullException.ThrowIfNull(phaseTwo);
        ArgumentNullException.ThrowIfNull(cleanupRemote);

        var frame = await phaseOne(cancellationToken);
        frame.Validate();
        var digest = Sha256Digest.Parse($"sha256:{Convert.ToHexString(frame.PublicKeySha256).ToLowerInvariant()}");
        if (digest is Result<Sha256Digest, ContractValidationError>.Failure)
        {
            throw new InvalidOperationException("Validated device digest was not canonical.");
        }

        VerifiedTemporaryRoot? root = null;
        EphemeralLabAuthority? authority = null;
        DisposablePostgresDatabase? database = null;
        var secret = RandomNumberGenerator.GetBytes(NodeTransportProtocol.MinimumClaimSecretBytes);
        WebApplication? application = null;
        Exception? operationFailure = null;
        try
        {
            root = VerifiedTemporaryRoot.Create();
            authority = new EphemeralLabAuthority(options.ListenAddress, TimeSpan.FromHours(1), root.Path);
            database = new DisposablePostgresDatabase(options.PostgresAdminConnection, options.DatabaseName);
            await database.CreateAndMigrateAsync(cancellationToken);
            var claim = new EnrollmentClaimReference(
                Guid.NewGuid(),
                new NodeUid(frame.NodeUid),
                frame.IdentityEpoch,
                ((Result<Sha256Digest, ContractValidationError>.Success)digest).Value);
            await database.SeedClaimAsync(claim, secret, DateTimeOffset.UtcNow.AddMinutes(10), cancellationToken);
            var repository = new PostgresNodeEnrollmentStateRepository(database.DataSource);
            application = BuildServer(options, repository, authority);
            await application.StartAsync(cancellationToken);
            await WriteEvidenceAsync(
                options.EvidenceDirectory,
                await phaseTwo(claim, repository, frame, secret, authority.CaCertificate, cancellationToken),
                cancellationToken);
        }
        catch (Exception exception)
        {
            operationFailure = exception;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            var cleanup = new CleanupCoordinator(
            [
                ("application", async token =>
                {
                    if (application is not null)
                    {
                        await application.DisposeAsync();
                    }
                }),
                ("wsl-temporary-root", cleanupRemote),
                ("database", async token =>
                {
                    if (database is not null)
                    {
                        await database.DropAsync(token);
                    }
                }),
                ("authority", _ =>
                {
                    authority?.Dispose();
                    return Task.CompletedTask;
                }),
                ("temporary-root", async _ =>
                {
                    if (root is not null)
                    {
                        await root.DisposeAsync();
                    }
                })
            ]);
            try
            {
                await cleanup.CleanupAsync(CancellationToken.None);
            }
            catch (Exception cleanupFailure) when (operationFailure is not null)
            {
                throw new AggregateException(
                    "C2 execution and cleanup failed; live proof is invalid.",
                    operationFailure,
                    cleanupFailure);
            }
        }

        if (operationFailure is not null)
        {
            ExceptionDispatchInfo.Capture(operationFailure).Throw();
        }
    }

    private static WebApplication BuildServer(
        LabHarnessOptions options,
        PostgresNodeEnrollmentStateRepository repository,
        EphemeralLabAuthority authority)
    {
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        var settings = new LabMtlsRuntimeSettings
        {
            Enabled = true,
            EnrollmentEndpoint = new(options.ListenAddress, options.EnrollmentPort),
            StreamEndpoint = new(options.ListenAddress, options.StreamPort),
            ServerCertificate = authority.ServerCertificate,
            CertificateLifetime = TimeSpan.FromHours(1),
            ClientCertificateValidation = (certificate, _, _) =>
                MtlsValidation.IsTrustedClient(certificate, authority.CaCertificate, DateTimeOffset.UtcNow)
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
        var output = new DirectoryInfo(directory);
        RejectRepositoryDestination(output.FullName);
        if (output.Exists)
        {
            if (output.LinkTarget is not null ||
                File.GetUnixFileMode(directory) != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute))
            {
                throw new IOException("Evidence output directory must be a verified owner-only non-link directory.");
            }
        }
        else
        {
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            output = new DirectoryInfo(directory);
            if (output.LinkTarget is not null ||
                File.GetUnixFileMode(directory) != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute))
            {
                throw new IOException("Evidence output directory could not be verified.");
            }
        }
        var path = System.IO.Path.Combine(directory, "c2-evidence.txt");
        if (File.Exists(path) || new FileInfo(path).LinkTarget is not null)
        {
            throw new IOException("Evidence output already exists or is a symbolic link.");
        }
        await using (var stream = new FileStream(
                         path,
                         FileMode.CreateNew,
                         FileAccess.Write,
                         FileShare.None,
                         bufferSize: 4096,
                         FileOptions.WriteThrough))
        await using (var writer = new StreamWriter(stream))
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await writer.WriteLineAsync(string.Join(
                Environment.NewLine,
                evidence.Select(item => $"{item.Name}={item.Value}").Append(string.Empty)));
            await writer.FlushAsync(cancellationToken);
        }

        if (new FileInfo(path).LinkTarget is not null ||
            File.GetUnixFileMode(path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
        {
            throw new IOException("Evidence output could not be verified as an owner-only regular file.");
        }
    }

    private static void RejectRepositoryDestination(string directory)
    {
        var candidate = ResolveExistingAncestor(Path.GetFullPath(directory));
        for (; candidate is not null; candidate = candidate.Parent)
        {
            var gitMetadata = Path.Combine(candidate.FullName, ".git");
            if (Directory.Exists(gitMetadata) || File.Exists(gitMetadata))
            {
                throw new IOException("Evidence output must be outside the repository.");
            }
        }
    }

    private static DirectoryInfo? ResolveExistingAncestor(string path)
    {
        var candidate = new DirectoryInfo(path);
        while (!candidate.Exists)
        {
            candidate = candidate.Parent
                ?? throw new IOException("Evidence output has no existing filesystem ancestor.");
        }

        return candidate.ResolveLinkTarget(returnFinalTarget: true) as DirectoryInfo ?? candidate;
    }
}
