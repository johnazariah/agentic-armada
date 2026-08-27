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
    private readonly string remoteRoot = $"armada-c2-{Guid.NewGuid():N}";

    public SshPhaseBridge(LabHarnessOptions options)
        : this(options, new ProcessSshProcessInvoker())
    {
    }

    public SshPhaseBridge(LabHarnessOptions options, ISshProcessInvoker ssh)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.ssh = ssh ?? throw new ArgumentNullException(nameof(ssh));
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

        var helperDigest = DigestHelper();
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
            $"set -eu; root=\"$HOME/.cache/{remoteRoot}\"; test \"$(stat -c '%u:%a' \"$root\")\" = \"$(id -u):700\"; rm -rf -- \"$root\"; test ! -e \"$root\"",
            null,
            cancellationToken,
            MaximumPhaseTwoResultsBytes);

    private async Task<string> StageHelperAsync(CancellationToken cancellationToken)
    {
        var digest = DigestHelper();
        const string reader = "while IFS=' ' read -r encoded_name encoded_contents extra; do test -n \"$encoded_name\" && test -n \"$encoded_contents\" && test -z \"$extra\" || exit 1; name=\"$(printf %s \"$encoded_name\" | base64 -d)\" || exit 1; case \"$name\" in \"\"|*[!A-Za-z0-9_.-]*) exit 1;; esac; printf %s \"$encoded_contents\" | base64 -d > \"$root/helper/$name\" || exit 1; done;";
        var payload = new StringBuilder();
        foreach (var file in Directory.EnumerateFiles(options.HelperDirectory, "*", SearchOption.TopDirectoryOnly)
                     .OrderBy(static file => file, StringComparer.Ordinal))
        {
            var name = Path.GetFileName(file);
            if (!PublishedFileNamePattern.IsMatch(name) || new FileInfo(file).LinkTarget is not null)
            {
                throw new IOException("Published helper contains an unsafe file.");
            }

            payload.Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(name)));
            payload.Append(' ');
            payload.Append(Convert.ToBase64String(await File.ReadAllBytesAsync(file, cancellationToken)));
            payload.Append('\n');
        }

        await RunAsync(
            $"set -eu; umask 077; root=\"$HOME/.cache/{remoteRoot}\"; mkdir -p \"$root/helper\"; chmod 700 \"$root\" \"$root/helper\"; test \"$(stat -c '%u:%a' \"$root\")\" = \"$(id -u):700\"; test \"$(stat -c '%u:%a' \"$root/helper\")\" = \"$(id -u):700\"; {reader}",
            payload.ToString(),
            cancellationToken,
            MaximumPhaseTwoResultsBytes);
        return digest;
    }

    private string DigestHelper()
    {
        var assembly = Path.Combine(options.HelperDirectory, "Armada.Lab.Mtls.WslClient.dll");
        return Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assembly))).ToLowerInvariant();
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
    private static readonly Regex PublishedFileNamePattern =
        new("^[A-Za-z0-9_.-]+$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
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
