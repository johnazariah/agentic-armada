using System.Diagnostics;
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

public sealed class SshPhaseBridge(LabHarnessOptions options)
{
    private readonly string remoteRoot = $"armada-c2-{Guid.NewGuid():N}";

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
            cancellationToken);
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
        return local;
    }

    public async Task<IReadOnlyList<EvidenceItem>> RunPhaseTwoAsync(
        EnrollmentClaimReference claim,
        INodeIdentityRegistry identities,
        PublicDeviceFrame frame,
        ReadOnlyMemory<byte> secret,
        X509Certificate2 caCertificate,
        CancellationToken cancellationToken)
    {
        var helperDigest = DigestHelper();
        var configuration = new PhaseTwoConfiguration(
            $"/home/johnaz/.cache/{remoteRoot}",
            new DevicePublicFrame(frame.NodeUid, frame.IdentityEpoch, frame.SubjectPublicKeyInfo, frame.PublicKeySha256, frame.CertificateSigningRequest, frame.FrameSha256),
            new Uri($"https://{options.ListenAddress}:{options.EnrollmentPort}"),
            new Uri($"https://{options.ListenAddress}:{options.StreamPort}"),
            claim.ClaimId.ToString("D"),
            secret.ToArray(),
            caCertificate.Export(X509ContentType.Cert));
        var input = JsonSerializer.Serialize(configuration, JsonOptions);
        using var process = Process.Start(SshInvocation.CreateStdinOnlyInvocation())
            ?? throw new IOException("Unable to start SSH.");
        await process.StandardInput.WriteLineAsync(LabHarnessCommandContract.PhaseTwoBootstrap(helperDigest, remoteRoot));
        await process.StandardInput.WriteLineAsync(input);
        await process.StandardInput.FlushAsync(cancellationToken);
        var readyLine = await process.StandardOutput.ReadLineAsync(cancellationToken);
        var ready = JsonSerializer.Deserialize<ReadyForRevocation>(readyLine ?? string.Empty, JsonOptions);
        if (ready is not { State: ReadyForRevocation.ReadyState, CompletedReportCount: 6, ReplayRejectionCode: Proto.TransportRejectionCode.ReplayConflict })
        {
            throw new IOException("WSL phase two did not reach the required revocation boundary.");
        }

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

        await process.StandardInput.WriteLineAsync("revocation-confirmed");
        process.StandardInput.Close();
        var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errors = await process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        if (process.ExitCode != 0)
        {
            throw new IOException($"SSH phase failed with exit code {process.ExitCode}: {errors}");
        }

        var results = JsonSerializer.Deserialize<IReadOnlyList<ProbeExecutionResult>>(output, JsonOptions)
            ?? throw new IOException("WSL phase two did not return probe results.");
        WslProbePlan.EnsureSatisfied(results);
        return results.Select(result => new EvidenceItem(result.Kind.ToString(), result.Disposition.ToString())).ToArray();
    }

    public Task CleanupAsync(CancellationToken cancellationToken) =>
        RunAsync(
            $"root=\"$HOME/.cache/{remoteRoot}\"; test \"$(stat -c '%u:%a' \"$root\")\" = \"$(id -u):700\"; rm -rf -- \"$root\"; test ! -e \"$root\"",
            null,
            cancellationToken);

    private async Task<string> StageHelperAsync(CancellationToken cancellationToken)
    {
        var digest = DigestHelper();
        var script = new StringBuilder($"umask 077; root=\"$HOME/.cache/{remoteRoot}\"; mkdir -p \"$root/helper\"; chmod 700 \"$root\" \"$root/helper\"; test \"$(stat -c '%u:%a' \"$root\")\" = \"$(id -u):700\"; test \"$(stat -c '%u:%a' \"$root/helper\")\" = \"$(id -u):700\";");
        foreach (var file in Directory.EnumerateFiles(options.HelperDirectory, "*", SearchOption.TopDirectoryOnly))
        {
            var name = Path.GetFileName(file);
            if (!PublishedFileNamePattern.IsMatch(name))
            {
                throw new IOException("Published helper has an unsafe file name.");
            }

            script.Append($" printf %s '{Convert.ToBase64String(await File.ReadAllBytesAsync(file, cancellationToken))}' | base64 -d > \"$root/helper/{name}\";");
        }

        await RunAsync(script.ToString(), null, cancellationToken);
        return digest;
    }

    private string DigestHelper()
    {
        var assembly = Path.Combine(options.HelperDirectory, "Armada.Lab.Mtls.WslClient.dll");
        return Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assembly))).ToLowerInvariant();
    }

    private static async Task<string> RunAsync(string script, string? payload, CancellationToken cancellationToken)
    {
        using var process = Process.Start(SshInvocation.CreateStdinOnlyInvocation())
            ?? throw new IOException("Unable to start SSH.");
        await process.StandardInput.WriteLineAsync(script);
        if (payload is not null)
        {
            await process.StandardInput.WriteAsync(payload.AsMemory(), cancellationToken);
        }
        await process.StandardInput.FlushAsync(cancellationToken);
        process.StandardInput.Close();
        var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errors = await process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        if (process.ExitCode != 0)
        {
            throw new IOException($"SSH phase failed with exit code {process.ExitCode}: {errors}");
        }

        return output.Trim();
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly Regex PublishedFileNamePattern =
        new("^[A-Za-z0-9_.-]+$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
}
