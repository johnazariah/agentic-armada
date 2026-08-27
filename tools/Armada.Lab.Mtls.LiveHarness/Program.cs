using Armada.Lab.Mtls.LiveHarness;

if (args.Contains("--help", StringComparer.Ordinal))
{
    Console.WriteLine("C2 is review-gated. Supply --preflight with explicit options to validate inputs; --execute is intentionally unavailable.");
    return;
}

if (!args.Contains("--preflight", StringComparer.Ordinal) &&
    !args.Contains("--execute", StringComparer.Ordinal))
{
    Console.Error.WriteLine("Refusing to run live lifecycle. Use --preflight after review approval.");
    Environment.ExitCode = 2;
    return;
}

var modeIndex = Array.FindIndex(args, static argument => argument is "--preflight" or "--execute");
var values = args
    .Skip(modeIndex + 1)
    .Chunk(2)
    .ToDictionary(
        static pair => pair.Length == 2 ? pair[0].TrimStart('-') : throw new ArgumentException("Options require values."),
        static pair => (string?)pair[1],
        StringComparer.Ordinal);
var options = LabHarnessOptions.Parse(values);
if (args.Contains("--preflight", StringComparer.Ordinal))
{
    Console.WriteLine("Preflight input validation passed. No CA, listener, database, claim, SSH, or WSL action was performed.");
    return;
}

ExecutionGate.RequireLiveApproval(args, Environment.GetEnvironmentVariable);
if (!OperatingSystem.IsMacOS())
{
    throw new PlatformNotSupportedException("The C2 live harness supports macOS only.");
}

var bridge = new SshPhaseBridge(options);
await new LiveHarnessExecution().RunAsync(
    options,
    bridge.RunPhaseOneAsync,
    bridge.RunPhaseTwoAsync,
    bridge.CleanupAsync,
    CancellationToken.None);
