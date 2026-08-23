using System.Security.Cryptography;

namespace Armada.Lab.Mtls.LiveHarness;

public sealed record PublicDeviceFrame(
    Guid NodeUid,
    long IdentityEpoch,
    byte[] SubjectPublicKeyInfo,
    byte[] PublicKeySha256,
    byte[] CertificateSigningRequest,
    byte[] FrameSha256)
{
    private const int DigestLength = 32;

    public static PublicDeviceFrame Create(
        Guid nodeUid,
        long identityEpoch,
        byte[] subjectPublicKeyInfo,
        byte[] certificateSigningRequest)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(identityEpoch);
        ArgumentNullException.ThrowIfNull(subjectPublicKeyInfo);
        ArgumentNullException.ThrowIfNull(certificateSigningRequest);
        var keyDigest = SHA256.HashData(subjectPublicKeyInfo);
        var frameDigest = SHA256.HashData(CanonicalBytes(
            nodeUid,
            identityEpoch,
            subjectPublicKeyInfo,
            keyDigest,
            certificateSigningRequest));
        return new(nodeUid, identityEpoch, subjectPublicKeyInfo, keyDigest, certificateSigningRequest, frameDigest);
    }

    public void Validate()
    {
        if (NodeUid == Guid.Empty || IdentityEpoch <= 0 ||
            PublicKeySha256.Length != DigestLength || FrameSha256.Length != DigestLength ||
            SubjectPublicKeyInfo.Length is 0 or > 4096 ||
            CertificateSigningRequest.Length is 0 or > 16384)
        {
            throw new ArgumentException("The public device frame is structurally invalid.");
        }

        if (!CryptographicOperations.FixedTimeEquals(PublicKeySha256, SHA256.HashData(SubjectPublicKeyInfo)) ||
            !CryptographicOperations.FixedTimeEquals(
                FrameSha256,
                SHA256.HashData(CanonicalBytes(
                    NodeUid,
                    IdentityEpoch,
                    SubjectPublicKeyInfo,
                    PublicKeySha256,
                    CertificateSigningRequest))))
        {
            throw new ArgumentException("The public device frame digest does not match its contents.");
        }
    }

    private static byte[] CanonicalBytes(
        Guid nodeUid,
        long identityEpoch,
        byte[] subjectPublicKeyInfo,
        byte[] publicKeySha256,
        byte[] certificateSigningRequest)
    {
        var length = 16 + sizeof(long) +
            sizeof(int) + subjectPublicKeyInfo.Length +
            sizeof(int) + publicKeySha256.Length +
            sizeof(int) + certificateSigningRequest.Length;
        var bytes = new byte[length];
        var offset = 0;
        nodeUid.TryWriteBytes(bytes.AsSpan(offset, 16));
        offset += 16;
        BitConverter.TryWriteBytes(bytes.AsSpan(offset, sizeof(long)), identityEpoch);
        offset += sizeof(long);
        Write(subjectPublicKeyInfo);
        Write(publicKeySha256);
        Write(certificateSigningRequest);
        return bytes;

        void Write(byte[] value)
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(offset, sizeof(int)), value.Length);
            offset += sizeof(int);
            value.CopyTo(bytes, offset);
            offset += value.Length;
        }
    }
}
