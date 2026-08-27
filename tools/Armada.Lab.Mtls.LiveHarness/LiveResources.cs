using System.Collections.Immutable;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Armada.Application;
using Armada.Contracts;
using Armada.Infrastructure.Postgres;
using Npgsql;
using System.Text.RegularExpressions;

namespace Armada.Lab.Mtls.LiveHarness;

// These resources are instantiated exclusively by the --execute path after ExecutionGate.
public sealed class EphemeralLabAuthority : ILabCertificateIssuer, IDisposable
{
    private readonly ECDsa caKey;
    private readonly X509Certificate2 caCertificate;

    public EphemeralLabAuthority(IPAddress listenerAddress, TimeSpan lifetime)
    {
        if (!LabHarnessOptions.IsExactUnicast(listenerAddress) ||
            lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromDays(31))
        {
            throw new ArgumentException("Lab authority requires an exact unicast address and bounded certificate lifetime.");
        }

        caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = DateTimeOffset.UtcNow;
        var request = new CertificateRequest(
            "CN=Armada C2 Ephemeral Lab CA",
            caKey,
            HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        caCertificate = request.CreateSelfSigned(now.AddMinutes(-1), now.Add(lifetime));
        ServerCertificate = CreateServerCertificate(listenerAddress, now, lifetime);
    }

    public X509Certificate2 ServerCertificate { get; }

    public X509Certificate2 CaCertificate => caCertificate;

    public Task<Result<IssuedCertificate, CertificateIssuanceFailure>> IssueAsync(
        CertificateIssuanceRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var deviceKey = ECDsa.Create();
        try
        {
            deviceKey.ImportSubjectPublicKeyInfo(request.Enrollment.DevicePublicKey.AsSpan(), out _);
        }
        catch (CryptographicException)
        {
            return Task.FromResult<Result<IssuedCertificate, CertificateIssuanceFailure>>(
                new Result<IssuedCertificate, CertificateIssuanceFailure>.Failure(
                    new("invalid-device-public-key", "The enrolled device key cannot be imported.")));
        }

        var certificateRequest = new CertificateRequest(
            $"CN=armada-node-{request.Enrollment.NodeUid}",
            deviceKey,
            HashAlgorithmName.SHA256);
        certificateRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.2") },
                false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri($"spiffe://armada.lab/node/{request.Enrollment.NodeUid}/epoch/{request.Enrollment.IdentityEpoch}"));
        certificateRequest.CertificateExtensions.Add(san.Build());
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7f;
        serial[0] |= 1;
        using var issued = certificateRequest.Create(
            caCertificate,
            request.NotBefore,
            request.ExpiresAt,
            serial);
        var leaf = issued.Export(X509ContentType.Cert);
        return Task.FromResult<Result<IssuedCertificate, CertificateIssuanceFailure>>(
            new Result<IssuedCertificate, CertificateIssuanceFailure>.Success(
                new(
                    Convert.ToHexString(serial),
                    ImmutableArray.CreateRange(leaf),
                    ImmutableArray.CreateRange(caCertificate.Export(X509ContentType.Cert)),
                    request.ExpiresAt)));
    }

    public void Dispose()
    {
        ServerCertificate.Dispose();
        caCertificate.Dispose();
        caKey.Dispose();
    }

    private X509Certificate2 CreateServerCertificate(IPAddress listenerAddress, DateTimeOffset now, TimeSpan lifetime)
    {
        using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Armada C2 Lab Server", serverKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") },
                false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(listenerAddress);
        request.CertificateExtensions.Add(san.Build());
        using var issued = request.Create(caCertificate, now.AddMinutes(-1), now.Add(lifetime), RandomNumberGenerator.GetBytes(16));
        return issued.CopyWithPrivateKey(serverKey);
    }
}

public sealed class DisposablePostgresDatabase : IAsyncDisposable
{
    private static readonly Regex DatabasePattern =
        new("^armada_c2_[a-f0-9]{32}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private readonly string adminConnectionString;
    private readonly string databaseName;
    private NpgsqlDataSource? dataSource;

    public DisposablePostgresDatabase(string adminConnectionString, string databaseName)
    {
        if (!DatabasePattern.IsMatch(databaseName))
        {
            throw new ArgumentException("Only an allowlisted C2 database can be managed.", nameof(databaseName));
        }

        this.adminConnectionString = adminConnectionString;
        this.databaseName = databaseName;
    }

    public NpgsqlDataSource DataSource =>
        dataSource ?? throw new InvalidOperationException("The disposable database has not been created.");

    public async Task CreateAndMigrateAsync(CancellationToken cancellationToken)
    {
        await using var admin = NpgsqlDataSource.Create(adminConnectionString);
        await using (var connection = await admin.OpenConnectionAsync(cancellationToken))
        await using (var command = new NpgsqlCommand($"CREATE DATABASE \"{databaseName}\";", connection))
        {
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var builder = new NpgsqlConnectionStringBuilder(adminConnectionString) { Database = databaseName };
        dataSource = NpgsqlDataSource.Create(builder.ConnectionString);
        await new PostgresMigrationRunner(dataSource).ApplyAsync(DateTimeOffset.UtcNow, cancellationToken);
    }

    public async Task SeedClaimAsync(
        EnrollmentClaimReference claim,
        ReadOnlyMemory<byte> secret,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        var verifier = SHA256.HashData(secret.Span);
        await using var connection = await DataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO armada_enrollment_claims
                (claim_id, secret_verifier, intended_node_uid, intended_identity_epoch,
                 intended_public_key_digest, intended_assurance, expires_at)
            VALUES (@claimId, @verifier, @nodeUid, @epoch, @digest, '{"profile":"c2-lab"}', @expiresAt);
            """,
            connection);
        command.Parameters.AddWithValue("claimId", claim.ClaimId);
        command.Parameters.AddWithValue("verifier", verifier);
        command.Parameters.AddWithValue("nodeUid", claim.NodeUid.Value);
        command.Parameters.AddWithValue("epoch", claim.IdentityEpoch);
        command.Parameters.AddWithValue("digest", claim.PublicKeyDigest.Value);
        command.Parameters.AddWithValue("expiresAt", expiresAt);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task DropAsync(CancellationToken cancellationToken)
    {
        dataSource?.Dispose();
        dataSource = null;
        await using var admin = NpgsqlDataSource.Create(adminConnectionString);
        await using var connection = await admin.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            $"DROP DATABASE IF EXISTS \"{databaseName}\" WITH (FORCE);",
            connection);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync() => await DropAsync(CancellationToken.None);
}
