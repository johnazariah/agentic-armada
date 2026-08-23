using Armada.Lab.Mtls.LiveHarness;

if (args.Contains("--help", StringComparer.Ordinal))
{
    Console.WriteLine("C2 is review-gated. Supply --preflight with explicit options to validate inputs; --execute is intentionally unavailable.");
    return;
}

if (!args.Contains("--preflight", StringComparer.Ordinal))
{
    Console.Error.WriteLine("Refusing to run live lifecycle. Use --preflight after review approval.");
    Environment.ExitCode = 2;
    return;
}

var values = args
    .SkipWhile(static argument => argument != "--preflight")
    .Skip(1)
    .Chunk(2)
    .ToDictionary(
        static pair => pair.Length == 2 ? pair[0].TrimStart('-') : throw new ArgumentException("Options require values."),
        static pair => (string?)pair[1],
        StringComparer.Ordinal);
_ = LabHarnessOptions.Parse(values);
Console.WriteLine("Preflight input validation passed. No CA, listener, database, claim, SSH, or WSL action was performed.");
