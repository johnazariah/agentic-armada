using System.Text.Json;
using Armada.Lab.Mtls.WslClient;

if (args.Length != 1 || args[0] is "--help" or "help")
{
    Console.WriteLine("Usage: Armada.Lab.Mtls.WslClient phase-one|phase-two < stdin-json");
    return;
}

var input = await Console.In.ReadToEndAsync();
if (string.IsNullOrWhiteSpace(input))
{
    throw new ArgumentException("The helper accepts phase configuration only from standard input.");
}

switch (args[0])
{
    case "phase-one":
    {
        var request = JsonSerializer.Deserialize<DeviceProvisioningRequest>(input, DevicePublicFrameJson.Options)
            ?? throw new ArgumentException("A phase-one request is required.");
        var frame = DeviceMaterialStore.Provision(request);
        Console.Out.WriteLine(JsonSerializer.Serialize(frame, DevicePublicFrameJson.Options));
        break;
    }
    case "phase-two":
    {
        var configuration = JsonSerializer.Deserialize<PhaseTwoConfiguration>(input, DevicePublicFrameJson.Options)
            ?? throw new ArgumentException("A phase-two configuration is required.");
        using var client = PhaseTwoClient.Create(configuration);
        var results = await new WslProbeRunner(client).RunAsync(
            configuration.Device,
            new ProbeTrustBundle(configuration.TrustedCaDer),
            DateTimeOffset.UtcNow,
            CancellationToken.None);
        WslProbePlan.EnsureSatisfied(results);
        Console.Out.WriteLine(JsonSerializer.Serialize(results, DevicePublicFrameJson.Options));
        break;
    }
    default:
        throw new ArgumentException("Only phase-one and phase-two commands are supported.");
}
