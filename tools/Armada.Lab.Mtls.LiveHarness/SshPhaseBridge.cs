using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Armada.Application;
using Armada.Contracts;
using Proto = Armada.Contracts.V1Alpha1;
using Armada.Lab.Mtls.WslClient;

namespace Armada.Lab.Mtls.LiveHarness;

public sealed record SshProcessResult(string StandardOutput, string StandardError, int ExitCode);

public sealed record PublishedHelperManifestEntry(string FileName, string Sha256);

public sealed class PublishedHelperManifest
{
    private static readonly Regex FileNamePattern =
        new("^[A-Za-z0-9_.-]+$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex DigestPattern =
        new("^[a-f0-9]{64}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private PublishedHelperManifest(
        IReadOnlyList<PublishedHelperManifestEntry> entries,
        string sha256SumContents)
    {
        Entries = entries;
        Sha256SumContents = sha256SumContents;
    }

    public IReadOnlyList<PublishedHelperManifestEntry> Entries { get; }

    public string Sha256SumContents { get; }

    public static PublishedHelperManifest LoadAndVerify(string manifestPath, string helperDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(manifestPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(helperDirectory);
        if (new FileInfo(manifestPath).LinkTarget is not null)
        {
            throw new IOException("The helper manifest must not be a symbolic link.");
        }

        var contents = File.ReadAllText(manifestPath, Encoding.ASCII);
        var entries = Parse(contents);
        var manifest = new PublishedHelperManifest(entries, string.Join('\n', entries.Select(static entry => $"{entry.Sha256}  helper/{entry.FileName}")) + '\n');
        manifest.VerifyDirectory(helperDirectory);
        return manifest;
    }

    public void VerifyDirectory(string helperDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(helperDirectory);
        var directory = new DirectoryInfo(helperDirectory);
        if (!directory.Exists || directory.LinkTarget is not null)
        {
            throw new IOException("The published helper directory must be an existing non-symbolic-link directory.");
        }

        var actual = directory.EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly)
            .OrderBy(static entry => entry.Name, StringComparer.Ordinal)
            .ToArray();
        if (actual.Any(static entry => entry is not FileInfo || entry.LinkTarget is not null) ||
            !actual.Select(static entry => entry.Name).SequenceEqual(Entries.Select(static entry => entry.FileName), StringComparer.Ordinal))
        {
            throw new IOException("The published helper files do not exactly match the trusted manifest.");
        }

        foreach (var entry in Entries)
        {
            var digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(helperDirectory, entry.FileName))))
                .ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(digest),
                    Encoding.ASCII.GetBytes(entry.Sha256)))
            {
                throw new IOException($"Published helper file '{entry.FileName}' does not match the trusted manifest.");
            }
        }

    }

    private static IReadOnlyList<PublishedHelperManifestEntry> Parse(string contents)
    {
        if (string.IsNullOrEmpty(contents) || !contents.EndsWith('\n'))
        {
            throw new IOException("The trusted helper manifest must be non-empty canonical newline-delimited text.");
        }

        var entries = contents.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(static line => line.Split("  ", StringSplitOptions.None))
            .Select(static parts => parts.Length == 2
                ? new PublishedHelperManifestEntry(parts[1], parts[0])
                : throw new IOException("The trusted helper manifest contains an invalid entry."))
            .OrderBy(static entry => entry.FileName, StringComparer.Ordinal)
            .ToArray();
        if (entries.Length == 0 ||
            entries.Any(entry => entry.FileName is "." or ".." ||
                                 !FileNamePattern.IsMatch(entry.FileName) ||
                                 !DigestPattern.IsMatch(entry.Sha256)) ||
            entries.Select(static entry => entry.FileName).Distinct(StringComparer.Ordinal).Count() != entries.Length ||
            !entries.Any(static entry => entry.FileName == "Armada.Lab.Mtls.WslClient.dll") ||
            !contents.Split('\n', StringSplitOptions.RemoveEmptyEntries).SequenceEqual(
                entries.Select(static entry => $"{entry.Sha256}  {entry.FileName}"),
                StringComparer.Ordinal))
        {
            throw new IOException("The trusted helper manifest must have sorted unique file names and lowercase SHA-256 digests.");
        }

        return entries;
    }
}

public interface ISshPhaseProcess : IAsyncDisposable
{
    Task WriteLineAsync(string value, CancellationToken cancellationToken);

    Task WriteAsync(string value, CancellationToken cancellationToken);

    Task FlushAsync(CancellationToken cancellationToken);

    Task<string?> ReadLineAsync(CancellationToken cancellationToken);

    Task<SshProcessResult> CompleteAsync(CancellationToken cancellationToken);
}

public interface ISshProcessInvoker
{
    Task<ISshPhaseProcess> StartAsync(CancellationToken cancellationToken);
}

public sealed class SshPhaseBridge
{
    private const int MaximumPhaseOneOutputBytes = 64 * 1024;
    private const int MaximumPhaseTwoResultsBytes = 64 * 1024;
    private readonly LabHarnessOptions options;
    private readonly ISshProcessInvoker ssh;
    private readonly PublishedHelperManifest manifest;
    private readonly string remoteRoot = $"armada-c2-{Guid.NewGuid():N}";

    public SshPhaseBridge(LabHarnessOptions options)
        : this(options, new ProcessSshProcessInvoker())
    {
    }

    public SshPhaseBridge(LabHarnessOptions options, ISshProcessInvoker ssh)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.ssh = ssh ?? throw new ArgumentNullException(nameof(ssh));
        manifest = PublishedHelperManifest.LoadAndVerify(options.HelperManifest, options.HelperDirectory);
    }

    public async Task<PublicDeviceFrame> RunPhaseOneAsync(CancellationToken cancellationToken)
    {
        var helperDigest = await StageHelperAsync(cancellationToken);
        var root = $"/home/johnaz/.cache/{remoteRoot}";
        var request = JsonSerializer.Serialize(
            new DeviceProvisioningRequest(root, options.NodeUid, options.IdentityEpoch),
            JsonOptions);
        var output = await RunAsync(
            LabHarnessCommandContract.PhaseOneBootstrap(helperDigest, remoteRoot),
            request,
            cancellationToken,
            MaximumPhaseOneOutputBytes);
        return ParsePublicFrame(output);
    }

    public async Task<IReadOnlyList<EvidenceItem>> RunPhaseTwoAsync(
        EnrollmentClaimReference claim,
        INodeIdentityRegistry identities,
        PublicDeviceFrame frame,
        ReadOnlyMemory<byte> secret,
        X509Certificate2 caCertificate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(identities);
        ArgumentNullException.ThrowIfNull(frame);
        ArgumentNullException.ThrowIfNull(caCertificate);
        frame.Validate();
        if (claim.NodeUid.Value != frame.NodeUid || claim.IdentityEpoch != frame.IdentityEpoch)
        {
            throw new ArgumentException("The enrolment claim must match the phase-one public frame.");
        }

        manifest.VerifyDirectory(options.HelperDirectory);
        var helperDigest = MainAssemblyDigest();
        var secretCopy = secret.ToArray();
        string input;
        try
        {
            var configuration = new PhaseTwoConfiguration(
                $"/home/johnaz/.cache/{remoteRoot}",
                new DevicePublicFrame(frame.NodeUid, frame.IdentityEpoch, frame.SubjectPublicKeyInfo, frame.PublicKeySha256, frame.CertificateSigningRequest, frame.FrameSha256),
                CreateEndpoint(options.ListenAddress, options.EnrollmentPort),
                CreateEndpoint(options.ListenAddress, options.StreamPort),
                claim.ClaimId.ToString("D"),
                secretCopy,
                caCertificate.Export(X509ContentType.Cert));
            configuration.Validate();
            input = JsonSerializer.Serialize(configuration, JsonOptions);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretCopy);
        }

        await using var process = await ssh.StartAsync(cancellationToken);
        await process.WriteLineAsync(LabHarnessCommandContract.PhaseTwoBootstrap(helperDigest, remoteRoot), cancellationToken);
        await process.WriteLineAsync(input, cancellationToken);
        await process.FlushAsync(cancellationToken);
        var ready = ParseReadyForRevocation(await process.ReadLineAsync(cancellationToken));

        var revoked = await identities.RevokeAsync(
            claim.NodeUid,
            claim.IdentityEpoch,
            "C2 controlled revocation proof",
            Guid.NewGuid(),
            cancellationToken);
        if (revoked is Result<NodeIdentityBinding, NodeIdentityRegistryFailure>.Failure)
        {
            throw new InvalidOperationException("Controller revocation failed.");
        }

        await process.WriteLineAsync("revocation-confirmed", cancellationToken);
        var completion = await process.CompleteAsync(cancellationToken);
        ThrowIfFailed(completion);
        var results = ParseProbeResults(completion.StandardOutput, MaximumPhaseTwoResultsBytes);
        WslProbePlan.EnsureSatisfied(results);
        return RedactedEvidence.Create(results.Select((result, index) =>
            new EvidenceItem($"probe-{index + 1}", result.Disposition.ToString())));
    }

    public Task CleanupAsync(CancellationToken cancellationToken) =>
        RunAsync(
            $"set -eu; root=\"$HOME/.cache/{remoteRoot}\"; test ! -L \"$root\"; test \"$(stat -c '%u:%a' \"$root\")\" = \"$(id -u):700\"; rm -rf -- \"$root\"; test ! -e \"$root\"",
            null,
            cancellationToken,
            MaximumPhaseTwoResultsBytes);

    private async Task<string> StageHelperAsync(CancellationToken cancellationToken)
    {
        manifest.VerifyDirectory(options.HelperDirectory);
        var digest = MainAssemblyDigest();
        const string reader = "while IFS=' ' read -r type encoded_name encoded_contents extra; do test -n \"$type\" && test -n \"$encoded_name\" && test -n \"$encoded_contents\" && test -z \"$extra\" || exit 1; name=\"$(printf %s \"$encoded_name\" | base64 -d)\" || exit 1; case \"$type:$name\" in file:|file:*[^A-Za-z0-9_.-]*) exit 1;; file:*) target=\"$root/helper/$name\";; manifest:helper.manifest) target=\"$root/helper.manifest\";; *) exit 1;; esac; test ! -e \"$target\" && test ! -L \"$target\" || exit 1; printf %s \"$encoded_contents\" | base64 -d > \"$target\" || exit 1; done;";
        var payload = new StringBuilder();
        foreach (var entry in manifest.Entries)
        {
            payload.Append("file ");
            payload.Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(entry.FileName)));
            payload.Append(' ');
            payload.Append(Convert.ToBase64String(await File.ReadAllBytesAsync(Path.Combine(options.HelperDirectory, entry.FileName), cancellationToken)));
            payload.Append('\n');
        }
        payload.Append("manifest ");
        payload.Append(Convert.ToBase64String("helper.manifest"u8));
        payload.Append(' ');
        payload.Append(Convert.ToBase64String(Encoding.ASCII.GetBytes(manifest.Sha256SumContents)));
        payload.Append('\n');

        await RunAsync(
            $"set -eu; umask 077; root=\"$HOME/.cache/{remoteRoot}\"; test ! -L \"$root\"; mkdir -p \"$root/helper\"; chmod 700 \"$root\" \"$root/helper\"; test ! -L \"$root\"; test \"$(stat -c '%u:%a' \"$root\")\" = \"$(id -u):700\"; test ! -L \"$root/helper\"; test \"$(stat -c '%u:%a' \"$root/helper\")\" = \"$(id -u):700\"; {reader}; test ! -L \"$root/helper.manifest\"; chmod 600 \"$root/helper.manifest\"; cd \"$root\"; sha256sum --strict --check helper.manifest",
            payload.ToString(),
            cancellationToken,
            MaximumPhaseTwoResultsBytes);
        return digest;
    }

    private string MainAssemblyDigest()
    {
        return manifest.Entries.Single(entry => entry.FileName == "Armada.Lab.Mtls.WslClient.dll").Sha256;
    }

    public static Uri CreateEndpoint(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!LabHarnessOptions.IsExactUnicast(address) || port is <= 0 or > 65535)
        {
            throw new ArgumentException("C2 endpoints require an exact unicast IP and valid port.");
        }

        return new UriBuilder(Uri.UriSchemeHttps, address.ToString(), port).Uri;
    }

    private async Task<string> RunAsync(
        string script,
        string? payload,
        CancellationToken cancellationToken,
        int maximumOutputBytes)
    {
        await using var process = await ssh.StartAsync(cancellationToken);
        await process.WriteLineAsync(script, cancellationToken);
        if (payload is not null)
        {
            await process.WriteAsync(payload, cancellationToken);
        }

        await process.FlushAsync(cancellationToken);
        var completion = await process.CompleteAsync(cancellationToken);
        ThrowIfFailed(completion);
        EnsureBoundedOutput(completion.StandardOutput, maximumOutputBytes);
        return completion.StandardOutput.Trim();
    }

    private PublicDeviceFrame ParsePublicFrame(string output)
    {
        try
        {
            var frame = JsonSerializer.Deserialize<DevicePublicFrame>(output, JsonOptions)
                ?? throw new IOException("WSL phase one did not return a public device frame.");
            var local = new PublicDeviceFrame(
                frame.NodeUid,
                frame.IdentityEpoch,
                frame.SubjectPublicKeyInfo,
                frame.PublicKeySha256,
                frame.CertificateSigningRequest,
                frame.FrameSha256);
            local.Validate();
            if (local.NodeUid != options.NodeUid || local.IdentityEpoch != options.IdentityEpoch)
            {
                throw new IOException("WSL phase one returned a public frame for an unexpected identity.");
            }

            return local;
        }
        catch (JsonException exception)
        {
            throw new IOException("WSL phase one did not return a valid public device frame.", exception);
        }
    }

    private static ReadyForRevocation ParseReadyForRevocation(string? readyLine)
    {
        try
        {
            var ready = JsonSerializer.Deserialize<ReadyForRevocation>(readyLine ?? string.Empty, JsonOptions);
            if (ready is not
                {
                    State: ReadyForRevocation.ReadyState,
                    CompletedReportCount: 4,
                    ReplayRejectionCode: Proto.TransportRejectionCode.ReplayConflict
                })
            {
                throw new IOException("WSL phase two did not reach the required revocation boundary.");
            }

            return ready;
        }
        catch (JsonException exception)
        {
            throw new IOException("WSL phase two did not return a valid revocation boundary.", exception);
        }
    }

    private static IReadOnlyList<ProbeExecutionResult> ParseProbeResults(string output, int maximumOutputBytes)
    {
        EnsureBoundedOutput(output, maximumOutputBytes);
        try
        {
            return JsonSerializer.Deserialize<IReadOnlyList<ProbeExecutionResult>>(output, JsonOptions)
                ?? throw new IOException("WSL phase two did not return probe results.");
        }
        catch (JsonException exception)
        {
            throw new IOException("WSL phase two did not return valid probe results.", exception);
        }
    }

    private static void ThrowIfFailed(SshProcessResult completion)
    {
        if (completion.ExitCode != 0)
        {
            throw new IOException($"SSH phase failed with exit code {completion.ExitCode}.");
        }
    }

    private static void EnsureBoundedOutput(string output, int maximumBytes)
    {
        if (Encoding.UTF8.GetByteCount(output) > maximumBytes)
        {
            throw new IOException("SSH returned more output than the phase contract permits.");
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
}

internal sealed class ProcessSshProcessInvoker : ISshProcessInvoker
{
    public Task<ISshPhaseProcess> StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var process = Process.Start(SshInvocation.CreateStdinOnlyInvocation())
            ?? throw new IOException("Unable to start SSH.");
        return Task.FromResult<ISshPhaseProcess>(new ProcessSshPhaseProcess(process));
    }
}

internal sealed class ProcessSshPhaseProcess(Process process) : ISshPhaseProcess
{
    private readonly Process process = process;
    private bool inputCompleted;

    public Task WriteLineAsync(string value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return process.StandardInput.WriteLineAsync(value);
    }

    public Task WriteAsync(string value, CancellationToken cancellationToken) =>
        process.StandardInput.WriteAsync(value.AsMemory(), cancellationToken);

    public Task FlushAsync(CancellationToken cancellationToken) =>
        process.StandardInput.FlushAsync(cancellationToken);

    public Task<string?> ReadLineAsync(CancellationToken cancellationToken) =>
        process.StandardOutput.ReadLineAsync(cancellationToken).AsTask();

    public async Task<SshProcessResult> CompleteAsync(CancellationToken cancellationToken)
    {
        if (!inputCompleted)
        {
            process.StandardInput.Close();
            inputCompleted = true;
        }

        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errors = process.StandardError.ReadToEndAsync(cancellationToken);
        await Task.WhenAll(output, errors, process.WaitForExitAsync(cancellationToken));
        return new SshProcessResult(output.Result, errors.Result, process.ExitCode);
    }

    public ValueTask DisposeAsync()
    {
        process.Dispose();
        return ValueTask.CompletedTask;
    }
}
