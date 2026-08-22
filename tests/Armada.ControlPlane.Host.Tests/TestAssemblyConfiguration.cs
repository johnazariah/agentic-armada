using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Armada.ControlPlane.Host.Tests;

internal sealed class TemporaryEnvironmentVariable : IDisposable
{
    private readonly string name;
    private readonly string? originalValue;

    public TemporaryEnvironmentVariable(string name, string value)
    {
        this.name = name;
        originalValue = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, value);
    }

    public void Dispose() => Environment.SetEnvironmentVariable(name, originalValue);
}
