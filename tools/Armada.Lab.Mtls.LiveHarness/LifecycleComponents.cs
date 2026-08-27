using System.Diagnostics;
using System.Net;

namespace Armada.Lab.Mtls.LiveHarness;

public sealed record LabCertificatePlan(
    string Subject,
    string ExactListenIp,
    TimeSpan Lifetime,
    bool ServerAuthentication,
    bool ClientAuthentication)
{
    public void ValidateServer(LabListenerPlan listener)
    {
        ArgumentNullException.ThrowIfNull(listener);
        listener.Validate();
        if (string.IsNullOrWhiteSpace(Subject) ||
            !IPAddress.TryParse(ExactListenIp, out var address) ||
            !LabHarnessOptions.IsExactUnicast(address) ||
            !string.Equals(ExactListenIp, listener.ExactListenIp, StringComparison.Ordinal) ||
            Lifetime <= TimeSpan.Zero || Lifetime > TimeSpan.FromDays(31) ||
            !ServerAuthentication || ClientAuthentication)
        {
            throw new ArgumentException("The server certificate plan must be an exact-IP, server-auth-only, bounded lab certificate.");
        }
    }
}

public sealed record LabListenerPlan(string ExactListenIp, int EnrollmentPort, int StreamPort)
{
    public void Validate()
    {
        if (!IPAddress.TryParse(ExactListenIp, out var address) ||
            !LabHarnessOptions.IsExactUnicast(address) ||
            EnrollmentPort is <= 0 or > 65535 ||
            StreamPort is <= 0 or > 65535 ||
            EnrollmentPort == StreamPort)
        {
            throw new ArgumentException("Listeners must use one exact unicast IP and distinct valid ports.");
        }
    }
}

public static class SshInvocation
{
    public static ProcessStartInfo CreateStdinOnlyInvocation()
    {
        var start = new ProcessStartInfo("ssh")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add("-T");
        start.ArgumentList.Add(LabHarnessCommandContract.SshHost);
        return start;
    }
}

public sealed record EvidenceItem(string Name, string Value);

public static class RedactedEvidence
{
    private static readonly string[] Forbidden =
        ["secret", "privatekey", "connectionstring", "csr", "postgres"];

    public static IReadOnlyList<EvidenceItem> Create(IEnumerable<EvidenceItem> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        var materialised = items.ToArray();
        if (materialised.Any(item =>
            string.IsNullOrWhiteSpace(item.Name) ||
            string.IsNullOrWhiteSpace(item.Value) ||
            Forbidden.Any(forbidden =>
                item.Name.Contains(forbidden, StringComparison.OrdinalIgnoreCase) ||
                item.Value.Contains(forbidden, StringComparison.OrdinalIgnoreCase))))
        {
            throw new ArgumentException("Evidence may contain only explicitly non-secret fields.");
        }

        return materialised;
    }
}

public sealed class CleanupCoordinator(IEnumerable<(string Name, Func<CancellationToken, Task> Action)> actions)
{
    public async Task CleanupAsync(CancellationToken cancellationToken)
    {
        var failures = new List<Exception>();
        using var cleanupTimeout = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        foreach (var (name, action) in actions)
        {
            try
            {
                await action(cleanupTimeout.Token);
            }
            catch (Exception exception)
            {
                failures.Add(new InvalidOperationException($"Cleanup step '{name}' failed.", exception));
            }
        }

        if (failures.Count != 0)
        {
            throw new AggregateException("C2 cleanup failed; live proof is invalid.", failures);
        }
    }
}
