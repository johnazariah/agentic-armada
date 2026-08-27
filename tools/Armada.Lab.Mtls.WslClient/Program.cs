using System.Text.Json;
using Armada.Lab.Mtls.WslClient;

if (args.Length != 1 || args[0] is "--help" or "help")
{
    Console.WriteLine("Usage: Armada.Lab.Mtls.WslClient phase-one|phase-two < stdin-json");
    return;
}

switch (args[0])
{
    case "phase-one":
    {
        var input = await Console.In.ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new ArgumentException("The helper accepts phase configuration only from standard input.");
        }

        var request = JsonSerializer.Deserialize<DeviceProvisioningRequest>(input, DevicePublicFrameJson.Options)
            ?? throw new ArgumentException("A phase-one request is required.");
        var frame = DeviceMaterialStore.Provision(request);
        Console.Out.WriteLine(JsonSerializer.Serialize(frame, DevicePublicFrameJson.Options));
        break;
    }
    case "phase-two":
    {
        var configurationLine = await Console.In.ReadLineAsync();
        if (string.IsNullOrWhiteSpace(configurationLine))
        {
            throw new ArgumentException("Phase two requires a JSON configuration line on standard input.");
        }

        var configuration = JsonSerializer.Deserialize<PhaseTwoConfiguration>(configurationLine, DevicePublicFrameJson.Options)
            ?? throw new ArgumentException("A phase-two configuration is required.");
        using var client = PhaseTwoClient.Create(configuration);
        var results = await new WslProbeRunner(client).RunAsync(
            configuration.Device,
            new ProbeTrustBundle(configuration.TrustedCaDer),
            new StandardInputRevocationPhase(),
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        WslProbePlan.EnsureSatisfied(results);
        Console.Out.WriteLine(JsonSerializer.Serialize(results, DevicePublicFrameJson.Options));
        break;
    }
    default:
        throw new ArgumentException("Only phase-one and phase-two commands are supported.");
}

sealed class StandardInputRevocationPhase : IRevocationPhase
{
    public Task PublishReadyAsync(ReadyForRevocation ready, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Console.Out.WriteLine(JsonSerializer.Serialize(ready, DevicePublicFrameJson.Options));
        Console.Out.Flush();
        return Task.CompletedTask;
    }

    public async Task WaitForConfirmationAsync(ReadyForRevocation ready, CancellationToken cancellationToken)
    {
        var line = await Console.In.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (!string.Equals(line, "revocation-confirmed", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Phase two requires the bridge confirmation 'revocation-confirmed'.");
        }
    }
}
