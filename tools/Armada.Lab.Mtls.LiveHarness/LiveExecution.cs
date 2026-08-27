using System.Collections.Immutable;
using System.Net;
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

public interface ILiveHarnessTemporaryRoot : IAsyncDisposable
{
    string Path { get; }
}

public interface ILiveHarnessAuthority : IDisposable
{
    X509Certificate2 CaCertificate { get; }

    X509Certificate2 ServerCertificate { get; }
}

public interface ILiveHarnessDatabase : IAsyncDisposable
{
    Task CreateAndMigrateAsync(CancellationToken cancellationToken);

    Task SeedClaimAsync(
        EnrollmentClaimReference claim,
        ReadOnlyMemory<byte> secret,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    Task DropAsync(CancellationToken cancellationToken);

    INodeIdentityRegistry CreateIdentityRegistry();
}

public interface ILiveHarnessRuntime
{
    ILiveHarnessTemporaryRoot CreateTemporaryRoot();

    ILiveHarnessAuthority CreateAuthority(IPAddress listenAddress, TimeSpan lifetime, string temporaryRoot);

    ILiveHarnessDatabase CreateDatabase(string adminConnectionString, string databaseName);

    Task<IAsyncDisposable> StartListenersAsync(
        LabHarnessOptions options,
        INodeIdentityRegistry identities,
        ILiveHarnessAuthority authority,
        CancellationToken cancellationToken);

    Task WriteEvidenceAsync(
        string directory,
        IReadOnlyList<EvidenceItem> items,
        CancellationToken cancellationToken);
}

[SupportedOSPlatform("macos")]
public sealed class VerifiedTemporaryRoot : ILiveHarnessTemporaryRoot
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

public sealed class LiveHarnessExecution
{
    // This method is reachable only from Program's two-factor execution branch.
    [SupportedOSPlatform("macos")]
    public async Task RunAsync(
        LabHarnessOptions options,
        Func<CancellationToken, Task<PublicDeviceFrame>> phaseOne,
        Func<EnrollmentClaimReference, INodeIdentityRegistry, PublicDeviceFrame, ReadOnlyMemory<byte>, X509Certificate2, CancellationToken, Task<IReadOnlyList<EvidenceItem>>> phaseTwo,
        Func<CancellationToken, Task> cleanupRemote,
        CancellationToken cancellationToken)
        => await RunAsync(options, phaseOne, phaseTwo, cleanupRemote, new MacLiveHarnessRuntime(), cancellationToken);

    public async Task RunAsync(
        LabHarnessOptions options,
        Func<CancellationToken, Task<PublicDeviceFrame>> phaseOne,
        Func<EnrollmentClaimReference, INodeIdentityRegistry, PublicDeviceFrame, ReadOnlyMemory<byte>, X509Certificate2, CancellationToken, Task<IReadOnlyList<EvidenceItem>>> phaseTwo,
        Func<CancellationToken, Task> cleanupRemote,
        ILiveHarnessRuntime runtime,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(phaseOne);
        ArgumentNullException.ThrowIfNull(phaseTwo);
        ArgumentNullException.ThrowIfNull(cleanupRemote);
        ArgumentNullException.ThrowIfNull(runtime);

        ILiveHarnessTemporaryRoot? root = null;
        ILiveHarnessAuthority? authority = null;
        ILiveHarnessDatabase? database = null;
        byte[]? secret = null;
        IAsyncDisposable? listener = null;
        Exception? operationFailure = null;
        try
        {
            var frame = await phaseOne(cancellationToken);
            frame.Validate();
            var digest = Sha256Digest.Parse($"sha256:{Convert.ToHexString(frame.PublicKeySha256).ToLowerInvariant()}");
            if (digest is Result<Sha256Digest, ContractValidationError>.Failure)
            {
                throw new InvalidOperationException("Validated device digest was not canonical.");
            }

            root = runtime.CreateTemporaryRoot();
            authority = runtime.CreateAuthority(options.ListenAddress, TimeSpan.FromHours(1), root.Path);
            database = runtime.CreateDatabase(options.PostgresAdminConnection, options.DatabaseName);
            await database.CreateAndMigrateAsync(cancellationToken);
            var claim = new EnrollmentClaimReference(
                Guid.NewGuid(),
                new NodeUid(frame.NodeUid),
                frame.IdentityEpoch,
                ((Result<Sha256Digest, ContractValidationError>.Success)digest).Value);
            secret = RandomNumberGenerator.GetBytes(NodeTransportProtocol.MinimumClaimSecretBytes);
            await database.SeedClaimAsync(claim, secret, DateTimeOffset.UtcNow.AddMinutes(10), cancellationToken);
            var identities = database.CreateIdentityRegistry();
            listener = await runtime.StartListenersAsync(options, identities, authority, cancellationToken);
            await runtime.WriteEvidenceAsync(
                options.EvidenceDirectory,
                await phaseTwo(claim, identities, frame, secret, authority.CaCertificate, cancellationToken),
                cancellationToken);
        }
        catch (Exception exception)
        {
            operationFailure = exception;
        }
        finally
        {
            if (secret is not null)
            {
                CryptographicOperations.ZeroMemory(secret);
            }

            var cleanup = new CleanupCoordinator(
            [
                ("listeners", async token =>
                {
                    if (listener is not null)
                    {
                        await listener.DisposeAsync();
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

    [SupportedOSPlatform("macos")]
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

    [SupportedOSPlatform("macos")]
    private sealed class MacLiveHarnessRuntime : ILiveHarnessRuntime
    {
        public ILiveHarnessTemporaryRoot CreateTemporaryRoot() => VerifiedTemporaryRoot.Create();

        public ILiveHarnessAuthority CreateAuthority(IPAddress listenAddress, TimeSpan lifetime, string temporaryRoot) =>
            new EphemeralLabAuthority(listenAddress, lifetime, temporaryRoot);

        public ILiveHarnessDatabase CreateDatabase(string adminConnectionString, string databaseName) =>
            new DisposablePostgresDatabase(adminConnectionString, databaseName);

        [SupportedOSPlatform("macos")]
        public async Task<IAsyncDisposable> StartListenersAsync(
            LabHarnessOptions options,
            INodeIdentityRegistry identities,
            ILiveHarnessAuthority authority,
            CancellationToken cancellationToken)
        {
            if (identities is not PostgresNodeEnrollmentStateRepository repository ||
                authority is not EphemeralLabAuthority ephemeralAuthority)
            {
                throw new InvalidOperationException("The macOS runtime requires PostgreSQL identities and an ephemeral lab authority.");
            }

            var application = BuildServer(options, repository, ephemeralAuthority);
            try
            {
                await application.StartAsync(cancellationToken);
                return application;
            }
            catch
            {
                await application.DisposeAsync();
                throw;
            }
        }

        public Task WriteEvidenceAsync(
            string directory,
            IReadOnlyList<EvidenceItem> items,
            CancellationToken cancellationToken) =>
            LiveHarnessExecution.WriteEvidenceAsync(directory, items, cancellationToken);
    }
}
