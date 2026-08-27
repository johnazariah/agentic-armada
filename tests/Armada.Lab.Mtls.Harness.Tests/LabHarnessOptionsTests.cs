using Armada.Lab.Mtls.LiveHarness;
using Armada.Application;
using Armada.Contracts;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Armada.Lab.Mtls.Harness.Tests;

public sealed class LabHarnessOptionsTests
{
    [Fact]
    public void Accepts_only_a_generated_disposable_database_and_distinct_lan_ports()
    {
        var options = LabHarnessOptions.Parse(Values());

        Assert.Equal("armada_c2_0123456789abcdef0123456789abcdef", options.DatabaseName);
        Assert.Equal(8443, options.EnrollmentPort);
    }

    [Theory]
    [InlineData("armada")]
    [InlineData("armada_lab")]
    [InlineData("armada_c2_UPPERCASE")]
    public void Rejects_unsafe_database_names(string database)
    {
        var values = Values();
        values["database"] = database;

        Assert.Throws<ArgumentException>(() => LabHarnessOptions.Parse(values));
    }

    [Fact]
    public void Rejects_postgres_credentials_in_command_line_options()
    {
        var values = Values();
        values["postgres-admin-connection"] = "Host=postgres;Username=admin;******";

        Assert.Throws<ArgumentException>(() => LabHarnessOptions.Parse(values));
    }

    [Fact]
    public void Bootstrap_has_no_remote_argument_and_uses_the_fixed_dotnet_path()
    {
        var command = LabHarnessCommandContract.PhaseOneBootstrap(
            new string('a', 64),
            "armada-c2_0123456789abcdef0123456789abcdef".Replace('_', '-'));

        Assert.Contains(LabHarnessCommandContract.WslDotnet, command, StringComparison.Ordinal);
        Assert.DoesNotContain("johnaz-phd-wsl", command, StringComparison.Ordinal);
        Assert.StartsWith("set -eu;", command, StringComparison.Ordinal);
        Assert.EndsWith(" phase-one", command, StringComparison.Ordinal);

        var phaseTwo = LabHarnessCommandContract.PhaseTwoBootstrap(
            new string('a', 64),
            "armada-c2_0123456789abcdef0123456789abcdef".Replace('_', '-'));
        Assert.EndsWith(" phase-two", phaseTwo, StringComparison.Ordinal);
        Assert.StartsWith("set -eu;", phaseTwo, StringComparison.Ordinal);
        Assert.Contains("test ! -L \"$root\"", command, StringComparison.Ordinal);
        Assert.Contains("test ! -L \"$root/helper\"", command, StringComparison.Ordinal);
        Assert.Contains("test ! -L \"$root\"", phaseTwo, StringComparison.Ordinal);
        Assert.Contains("test ! -L \"$root/helper\"", phaseTwo, StringComparison.Ordinal);
        Assert.Contains("test ! -L \"$root/device\"", phaseTwo, StringComparison.Ordinal);
    }

    [Fact]
    public void Endpoint_builder_brackets_an_exact_ipv6_literal()
    {
        var endpoint = SshPhaseBridge.CreateEndpoint(IPAddress.Parse("2001:db8::1"), 8443);

        Assert.Equal("https://[2001:db8::1]:8443/", endpoint.AbsoluteUri);
    }

    [Theory]
    [InlineData("relative/evidence")]
    [InlineData(".")]
    public void Rejects_relative_evidence_paths(string evidencePath)
    {
        var values = Values();
        values["evidence-directory"] = evidencePath;

        Assert.Throws<ArgumentException>(() => LabHarnessOptions.Parse(values));
    }

    [Theory]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("ff02::1")]
    public void Rejects_non_unicast_listener_addresses(string address)
    {
        var values = Values();
        values["listen-ip"] = address;

        Assert.Throws<ArgumentException>(() => LabHarnessOptions.Parse(values));
    }

    [Fact]
    public void Bootstrap_rejects_unsafe_shell_tokens()
    {
        Assert.Throws<ArgumentException>(() =>
            LabHarnessCommandContract.PhaseOneBootstrap("'; touch unsafe; #", "armada-c2-0123456789abcdef0123456789abcdef"));
        Assert.Throws<ArgumentException>(() =>
            LabHarnessCommandContract.PhaseTwoBootstrap(new string('a', 64), "../unsafe"));
    }

    [Fact]
    public void Public_device_frame_rejects_a_substituted_key_or_csr()
    {
        var frame = Frame();
        frame.Validate();

        Assert.Throws<ArgumentException>(() =>
            (frame with { CertificateSigningRequest = [9, 5, 6] }).Validate());
    }

    [Fact]
    public void Public_device_frame_rejects_a_csr_for_another_p256_key()
    {
        var frame = Frame();
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var otherCsr = new CertificateRequest("CN=other", other, HashAlgorithmName.SHA256).CreateSigningRequest();

        Assert.Throws<ArgumentException>(() =>
            PublicDeviceFrame.Create(frame.NodeUid, frame.IdentityEpoch, frame.SubjectPublicKeyInfo, otherCsr).Validate());
    }

    [Fact]
    public void Public_device_frame_rejects_an_invalid_spki()
    {
        Assert.Throws<ArgumentException>(() =>
            PublicDeviceFrame.Create(Guid.NewGuid(), 1, [1, 2, 3], [4, 5, 6]).Validate());
    }

    [Fact]
    public void Ssh_invocation_supplies_only_the_fixed_host_and_no_remote_command()
    {
        var invocation = SshInvocation.CreateStdinOnlyInvocation();

        Assert.Equal(["-T", LabHarnessCommandContract.SshHost], invocation.ArgumentList);
        Assert.True(invocation.RedirectStandardInput);
    }

    [Fact]
    public async Task Cleanup_runs_every_step_and_fails_after_an_error()
    {
        var steps = new List<string>();
        var cleanup = new CleanupCoordinator(
        [
            ("server", _ => { steps.Add("server"); return Task.CompletedTask; }),
            ("database", _ => throw new InvalidOperationException("drop failed")),
            ("temporary-root", _ => { steps.Add("temporary-root"); return Task.CompletedTask; })
        ]);

        await Assert.ThrowsAsync<AggregateException>(() => cleanup.CleanupAsync(CancellationToken.None));
        Assert.Equal(["server", "temporary-root"], steps);
    }

    [Fact]
    public async Task Cleanup_ignores_a_cancelled_caller_token_and_runs_every_step()
    {
        var steps = new List<string>();
        var cleanup = new CleanupCoordinator(
        [
            ("first", token => { Assert.False(token.IsCancellationRequested); steps.Add("first"); return Task.CompletedTask; }),
            ("second", token => { Assert.False(token.IsCancellationRequested); steps.Add("second"); return Task.CompletedTask; })
        ]);
        using var callerCancellation = new CancellationTokenSource();
        callerCancellation.Cancel();

        await cleanup.CleanupAsync(callerCancellation.Token);

        Assert.Equal(["first", "second"], steps);
    }

    [Fact]
    public void Evidence_rejects_secret_bearing_fields()
    {
        Assert.Throws<ArgumentException>(() =>
            RedactedEvidence.Create([new("claimSecret", "not retained")]));
    }

    [Fact]
    public void Evidence_rejects_sensitive_values_with_an_allowed_field_name()
    {
        Assert.Throws<ArgumentException>(() =>
            RedactedEvidence.Create([new("certificateFingerprint", "Host=postgres;Password=secret")]));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("224.0.0.1")]
    public void Certificate_plan_requires_the_same_exact_unicast_listener_address(string address)
    {
        var listener = new LabListenerPlan("192.0.2.20", 8443, 9443);
        var plan = new LabCertificatePlan("CN=lab", address, TimeSpan.FromHours(1), true, false);

        Assert.Throws<ArgumentException>(() => plan.ValidateServer(listener));
    }

    [Fact]
    public void Execution_gate_requires_both_command_and_explicit_environment_approval()
    {
        Assert.Throws<InvalidOperationException>(() =>
            ExecutionGate.RequireLiveApproval(["--execute"], _ => null));
        Assert.Throws<InvalidOperationException>(() =>
            ExecutionGate.RequireLiveApproval(["--preflight"], _ => "approved"));

        ExecutionGate.RequireLiveApproval(["--execute"], _ => "approved");
    }

    [Theory]
    [InlineData("armada_c2_0123456789abcdef0123456789abcdef;DROP DATABASE armada")]
    [InlineData("armada_c2_0123456789abcdef0123456789abcdeF")]
    [InlineData("armada")]
    public void Disposable_database_rejects_non_allowlisted_names_before_sql_is_constructed(string name)
    {
        Assert.Throws<ArgumentException>(() =>
            new DisposablePostgresDatabase("Host=localhost;Database=postgres", name));
    }

    [Fact]
    public async Task Execution_orders_every_stage_and_cleanup_through_injectable_ports()
    {
        var steps = new List<string>();
        var runtime = new FakeRuntime(steps);
        var frame = Frame();

        await new LiveHarnessExecution().RunAsync(
            LabHarnessOptions.Parse(Values()),
            "Host=offline;Database=armada",
            _ =>
            {
                steps.Add("phase-one");
                return Task.FromResult(frame);
            },
            (_, _, _, _, _, _) =>
            {
                steps.Add("phase-two");
                return Task.FromResult<IReadOnlyList<EvidenceItem>>([new("Enrollment", "EnrollmentAccepted")]);
            },
            _ =>
            {
                steps.Add("wsl-cleanup");
                return Task.CompletedTask;
            },
            runtime,
            CancellationToken.None);

        Assert.Equal(
        [
            "phase-one", "temporary-root", "authority", "database", "migrate", "seed",
            "registry", "listeners", "phase-two", "evidence", "listeners-cleanup",
            "wsl-cleanup", "database-drop", "authority-cleanup", "temporary-root-cleanup"
        ],
        steps);
    }

    [Fact]
    public async Task Execution_aggregates_body_and_cleanup_failures_after_every_cleanup_step()
    {
        var steps = new List<string>();
        var runtime = new FakeRuntime(steps, failDatabaseDrop: true, failListenerDispose: true);

        var failure = await Assert.ThrowsAsync<AggregateException>(() =>
            new LiveHarnessExecution().RunAsync(
                LabHarnessOptions.Parse(Values()),
                "Host=offline;Database=armada",
                _ => Task.FromResult(Frame()),
                (_, _, _, _, _, _) => throw new InvalidOperationException("phase two failed"),
                _ =>
                {
                    steps.Add("wsl-cleanup");
                    return Task.CompletedTask;
                },
                runtime,
                CancellationToken.None));

        Assert.Contains(failure.InnerExceptions, exception => exception.Message == "phase two failed");
        Assert.Equal(
        [
            "temporary-root", "authority", "database", "migrate", "seed", "registry",
            "listeners", "listeners-cleanup", "wsl-cleanup", "database-drop",
            "authority-cleanup", "temporary-root-cleanup"
        ],
        steps);
    }

    [Fact]
    public async Task Execution_cleans_remote_state_when_phase_one_validation_fails()
    {
        var steps = new List<string>();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            new LiveHarnessExecution().RunAsync(
                LabHarnessOptions.Parse(Values()),
                "Host=offline;Database=armada",
                _ =>
                {
                    steps.Add("phase-one");
                    return Task.FromResult(PublicDeviceFrame.Create(Guid.NewGuid(), 1, [1], [2]));
                },
                (_, _, _, _, _, _) => throw new NotSupportedException(),
                _ =>
                {
                    steps.Add("wsl-cleanup");
                    return Task.CompletedTask;
                },
                new FakeRuntime(steps),
                CancellationToken.None));

        Assert.Equal(["phase-one", "wsl-cleanup"], steps);
    }

    private static Dictionary<string, string?> Values() => new(StringComparer.Ordinal)
    {
        ["listen-ip"] = "192.0.2.20",
        ["enrollment-port"] = "8443",
        ["stream-port"] = "9443",
        ["database"] = "armada_c2_0123456789abcdef0123456789abcdef",
        ["evidence-directory"] = "/tmp/armada-evidence",
        ["helper-directory"] = AppContext.BaseDirectory,
        ["node-uid"] = "01234567-89ab-cdef-0123-456789abcdef",
        ["identity-epoch"] = "1"
    };

    private static PublicDeviceFrame Frame()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = key.ExportSubjectPublicKeyInfo();
        var csr = new CertificateRequest("CN=armada-node", key, HashAlgorithmName.SHA256).CreateSigningRequest();
        return PublicDeviceFrame.Create(Guid.NewGuid(), 1, spki, csr);
    }

    private sealed class FakeRuntime(List<string> steps, bool failDatabaseDrop = false, bool failListenerDispose = false) : ILiveHarnessRuntime
    {
        public ILiveHarnessTemporaryRoot CreateTemporaryRoot()
        {
            steps.Add("temporary-root");
            return new FakeRoot(steps);
        }

        public ILiveHarnessAuthority CreateAuthority(IPAddress _, TimeSpan __, string ___)
        {
            steps.Add("authority");
            return new FakeAuthority(steps);
        }

        public ILiveHarnessDatabase CreateDatabase(string _, string __)
        {
            steps.Add("database");
            return new FakeDatabase(steps, failDatabaseDrop);
        }

        public Task<IAsyncDisposable> StartListenersAsync(
            LabHarnessOptions _,
            INodeIdentityRegistry __,
            ILiveHarnessAuthority ___,
            CancellationToken ____)
        {
            steps.Add("listeners");
            return Task.FromResult<IAsyncDisposable>(new FakeListener(steps, failListenerDispose));
        }

        public Task WriteEvidenceAsync(string _, IReadOnlyList<EvidenceItem> __, CancellationToken ___)
        {
            steps.Add("evidence");
            return Task.CompletedTask;
        }
    }

    private sealed class FakeRoot(List<string> steps) : ILiveHarnessTemporaryRoot
    {
        public string Path => "/fake";

        public ValueTask DisposeAsync()
        {
            steps.Add("temporary-root-cleanup");
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeAuthority(List<string> steps) : ILiveHarnessAuthority
    {
        public X509Certificate2 CaCertificate => null!;
        public X509Certificate2 ServerCertificate => null!;

        public void Dispose()
        {
            steps.Add("authority-cleanup");
        }
    }

    private sealed class FakeDatabase(List<string> steps, bool failDrop) : ILiveHarnessDatabase
    {
        public Task CreateAndMigrateAsync(CancellationToken _)
        {
            steps.Add("migrate");
            return Task.CompletedTask;
        }

        public Task SeedClaimAsync(EnrollmentClaimReference _, ReadOnlyMemory<byte> __, DateTimeOffset ___, CancellationToken ____)
        {
            steps.Add("seed");
            return Task.CompletedTask;
        }

        public Task DropAsync(CancellationToken _)
        {
            steps.Add("database-drop");
            return failDrop ? Task.FromException(new IOException("drop failed")) : Task.CompletedTask;
        }

        public INodeIdentityRegistry CreateIdentityRegistry()
        {
            steps.Add("registry");
            return new FakeIdentityRegistry();
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeListener(List<string> steps, bool failDispose) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            steps.Add("listeners-cleanup");
            return failDispose
                ? ValueTask.FromException(new IOException("listener dispose failed"))
                : ValueTask.CompletedTask;
        }
    }

    private sealed class FakeIdentityRegistry : INodeIdentityRegistry
    {
        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> ResolveAsync(NodeUid _, long __, string ___, string ____, CancellationToken _____) =>
            throw new NotSupportedException();

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RegisterAsync(NodeIdentityBinding _, CancellationToken __) =>
            throw new NotSupportedException();

        public Task<Result<NodeIdentityBinding, NodeIdentityRegistryFailure>> RevokeAsync(NodeUid _, long __, string ___, Guid ____, CancellationToken _____) =>
            throw new NotSupportedException();
    }
}
