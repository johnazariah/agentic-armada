using System.Text.Json;
using Armada.Contracts;
using Armada.NodeAgent;

var options = ParseOptions(args);
var fileSystem = new PhysicalBootstrapFileSystem();
var clock = new SystemClock();

switch (args.FirstOrDefault())
{
    case "package":
        Require(options, "source", "output", "package-id", "version", "issuer", "key-id", "private-key");
        var privateKey = File.ReadAllText(options["private-key"]);
        Write(new BootstrapPackager(fileSystem, clock).Create(
            options["source"],
            options["output"],
            new(options["issuer"], options["key-id"], privateKey),
            options["package-id"],
            options["version"]));
        break;
    case "install":
        Require(options, "package", "trust", "install-root", "state-root");
        var trustResult = BootstrapPackageFormat.DeserializeTrust(File.ReadAllText(options["trust"]));
        if (trustResult is Result<BootstrapTrustConfiguration, BootstrapFailure>.Failure trustFailure)
        {
            Fail(trustFailure.Error);
            break;
        }
        Write(new BootstrapInstaller(fileSystem, clock).Install(
            options["package"],
            ((Result<BootstrapTrustConfiguration, BootstrapFailure>.Success)trustResult).Value,
            options["install-root"],
            options["state-root"]));
        break;
    case "status":
        Require(options, "install-root", "state-root");
        Write(new BootstrapInstaller(fileSystem, clock).Status(options["install-root"], options["state-root"]));
        break;
    default:
        throw new ArgumentException("Usage: bootstrap package|install|status --name value");
}

static Dictionary<string, string> ParseOptions(string[] arguments)
{
    if (arguments.Length < 1 || (arguments.Length - 1) % 2 != 0)
    {
        throw new ArgumentException("Options must be supplied as --name value pairs.");
    }

    return arguments.Skip(1).Chunk(2).ToDictionary(
        static pair => pair[0].StartsWith("--", StringComparison.Ordinal)
            ? pair[0][2..]
            : throw new ArgumentException("Option names must begin with --."),
        static pair => pair[1],
        StringComparer.Ordinal);
}

static void Require(IReadOnlyDictionary<string, string> options, params string[] names)
{
    if (names.Any(name => !options.ContainsKey(name)))
    {
        throw new ArgumentException("A required bootstrap option is missing.");
    }
}

static void Write<T>(Result<T, BootstrapFailure> result)
{
    switch (result)
    {
        case Result<T, BootstrapFailure>.Success success:
            Console.WriteLine(JsonSerializer.Serialize(success.Value));
            break;
        case Result<T, BootstrapFailure>.Failure failure:
            Fail(failure.Error);
            break;
        default:
            Fail(new("bootstrap-result-invalid", "The bootstrap operation returned an unsupported result."));
            break;
    }
}

static void Fail(BootstrapFailure failure)
{
    Console.Error.WriteLine($"{failure.Code}: {failure.Message}");
    Environment.ExitCode = 1;
}

file sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
