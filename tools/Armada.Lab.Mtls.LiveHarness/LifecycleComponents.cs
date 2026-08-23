using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace Armada.Lab.Mtls.LiveHarness;

public sealed record LabCertificatePlan(
    string Subject,
    string ExactListenIp,
    TimeSpan Lifetime,
    bool ServerAuthentication,
    bool ClientAuthentication)
{
    public void ValidateServer()
    {
        if (string.IsNullOrWhiteSpace(Subject) ||
            !System.Net.IPAddress.TryParse(ExactListenIp, out _) ||
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
        _ = LabHarnessOptions.Parse(new Dictionary<string, string?>
        {
            ["postgres-admin-connection"] = "not-used-for-listener-validation",
            ["listen-ip"] = ExactListenIp,
            ["enrollment-port"] = EnrollmentPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["stream-port"] = StreamPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["database"] = "armada_c2_00000000000000000000000000000000",
            ["evidence-directory"] = Path.GetTempPath()
        });
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
            Forbidden.Any(forbidden => item.Name.Contains(forbidden, StringComparison.OrdinalIgnoreCase))))
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
        foreach (var (name, action) in actions)
        {
            try
            {
                await action(cancellationToken);
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
