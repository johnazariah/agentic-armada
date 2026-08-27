namespace Armada.Lab.Mtls.LiveHarness;

public static class ExecutionGate
{
    public const string ApprovalVariable = "ARMADA_C2_LIVE_APPROVAL";
    private const string ApprovalValue = "approved";

    public static void RequireLiveApproval(IReadOnlyList<string> arguments, Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(environment);

        if (!arguments.Contains("--execute", StringComparer.Ordinal) ||
            !string.Equals(environment(ApprovalVariable), ApprovalValue, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Live execution requires --execute and an explicit ARMADA_C2_LIVE_APPROVAL=approved environment value.");
        }
    }
}
