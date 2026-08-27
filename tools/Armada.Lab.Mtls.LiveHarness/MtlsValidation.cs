using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace Armada.Lab.Mtls.LiveHarness;

public static class MtlsValidation
{
    public static bool IsTrustedClient(
        X509Certificate2? certificate,
        X509Certificate2 caCertificate,
        DateTimeOffset now)
    {
        if (certificate is null ||
            certificate.NotBefore.ToUniversalTime() > now.UtcDateTime ||
            certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime ||
            !HasClientAuthenticationEku(certificate))
        {
            return false;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(caCertificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = now.UtcDateTime;
        return chain.Build(certificate);
    }

    public static bool IsExpectedClient(
        X509Certificate2? certificate,
        X509Certificate2 caCertificate,
        Guid nodeUid,
        long identityEpoch,
        DateTimeOffset now)
    {
        if (certificate is null || identityEpoch <= 0 ||
            !IsTrustedClient(certificate, caCertificate, now) ||
            !HasExactSpiffeSan(certificate, nodeUid, identityEpoch))
        {
            return false;
        }

        return true;
    }

    private static bool HasClientAuthenticationEku(X509Certificate2 certificate) =>
        certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Any(extension => extension.EnhancedKeyUsages
                .Cast<Oid>()
                .Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2"));

    private static bool HasExactSpiffeSan(X509Certificate2 certificate, Guid nodeUid, long identityEpoch)
    {
        var expected = $"spiffe://armada.lab/node/{nodeUid:D}/epoch/{identityEpoch}";
        return certificate.Extensions
            .OfType<X509Extension>()
            .Any(extension =>
                extension.Oid?.Value == "2.5.29.17" &&
                extension.Format(false).Contains(expected, StringComparison.Ordinal));
    }
}
