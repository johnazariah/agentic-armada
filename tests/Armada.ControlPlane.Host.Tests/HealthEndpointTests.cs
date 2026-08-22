using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Armada.ControlPlane.Host.Tests;

public sealed class HealthEndpointTests : IClassFixture<HealthEndpointTests.UnconfiguredHostFactory>
{
    private readonly HttpClient client;

    public HealthEndpointTests(UnconfiguredHostFactory factory)
    {
        client = factory.CreateClient();
    }

    [Fact]
    public async Task Liveness_is_available_while_default_configuration_remains_not_ready()
    {
        var live = await client.GetAsync("/health/live");
        var ready = await client.GetAsync("/health/ready");

        Assert.True(live.IsSuccessStatusCode);
        Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable, ready.StatusCode);
    }

    [Fact]
    public void Injected_kestrel_endpoint_is_rejected_before_a_server_starts()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Kestrel:Endpoints:external:Url"] = "http://0.0.0.0:5080"
            });

        var error = Assert.Throws<InvalidOperationException>(
            () => ControlPlaneHostBootstrap.Configure(builder, ControlPlaneConfigurationTests.ValidOptions()));

        Assert.Contains("Kestrel endpoint configuration is prohibited", error.ToString());
    }

    [Fact]
    public void Generic_hosting_port_and_preference_inputs_are_rejected_before_a_server_starts()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["http_ports"] = "5080",
                ["https_ports"] = "5443",
                ["preferHostingUrls"] = "true"
            });

        var error = Assert.Throws<InvalidOperationException>(
            () => ControlPlaneHostBootstrap.Configure(builder, ControlPlaneConfigurationTests.ValidOptions()));

        Assert.Contains("HTTP and HTTPS port configuration is prohibited", error.ToString());
        Assert.Contains("Hosting URL preference is prohibited", error.ToString());
    }

    [Fact]
    public void Raw_unsafe_hosting_inputs_cannot_be_masked_by_empty_armada_values()
    {
        using var rawUrls = new TemporaryEnvironmentVariable(
            "ASPNETCORE_URLS",
            "http://0.0.0.0:5080");
        using var rawPorts = new TemporaryEnvironmentVariable("DOTNET_HTTP_PORTS", "5081");
        using var rawPreference = new TemporaryEnvironmentVariable(
            "ASPNETCORE_PREFERHOSTINGURLS",
            "true");
        using var maskedUrls = new TemporaryEnvironmentVariable("ARMADA_ASPNETCORE_URLS", string.Empty);
        using var maskedPorts = new TemporaryEnvironmentVariable("ARMADA_DOTNET_HTTP_PORTS", string.Empty);
        using var maskedPreference = new TemporaryEnvironmentVariable(
            "ARMADA_ASPNETCORE_PREFERHOSTINGURLS",
            string.Empty);
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        ControlPlaneHostConfiguration.AddSources(builder.Configuration, Environments.Development, []);

        Assert.True(string.IsNullOrEmpty(builder.Configuration["ASPNETCORE_URLS"]));
        Assert.True(string.IsNullOrEmpty(builder.Configuration["DOTNET_HTTP_PORTS"]));
        Assert.True(string.IsNullOrEmpty(builder.Configuration["ASPNETCORE_PREFERHOSTINGURLS"]));

        var error = Assert.Throws<InvalidOperationException>(
            () => ControlPlaneHostApplication.Build(builder));

        Assert.Contains("URL configuration is prohibited", error.Message);
        Assert.Contains("HTTP and HTTPS port configuration is prohibited", error.Message);
        Assert.Contains("Hosting URL preference is prohibited", error.Message);
    }

    [Fact]
    public async Task Valid_configuration_starts_a_kestrel_host_and_serves_liveness()
    {
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddInMemoryCollection(ValidHostConfiguration());
        var options = builder.Configuration.GetSection(ControlPlaneOptions.SectionName).Get<ControlPlaneOptions>();
        Assert.NotNull(options);
        Assert.Empty(ControlPlaneConfiguration.Validate(options));

        await using var app = ControlPlaneHostApplication.Build(builder);
        try
        {
            await app.StartAsync();

            var addresses = app.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()?.Addresses;
            var address = Assert.Single(addresses ?? []);
            using var client = new HttpClient { BaseAddress = new Uri(address) };

            var live = await client.GetAsync("/health/live");

            Assert.True(live.IsSuccessStatusCode);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public async Task Published_armada_configuration_starts_and_returns_readiness_with_injected_dependencies()
    {
        const string connectionString =
            "Host=127.0.0.1;Port=5432;Database=armada_lab;Username=armada_lab";
        using var environment = new TemporaryEnvironmentVariable(
            "ARMADA_ControlPlane__Postgres__ConnectionString",
            connectionString);
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        ControlPlaneHostConfiguration.AddSources(builder.Configuration, builder.Environment.EnvironmentName, []);
        var configuration = ValidHostConfiguration();
        configuration.Remove("ControlPlane:Postgres:ConnectionString");
        builder.Configuration.AddInMemoryCollection(configuration);
        builder.Services.AddSingleton<IRestoreEvidenceVerifier>(new VerifiedEvidence());
        builder.Services.AddSingleton<IPostgresReadinessProbe>(new ReachablePostgres());

        var options = builder.Configuration.GetSection(ControlPlaneOptions.SectionName).Get<ControlPlaneOptions>();
        Assert.NotNull(options);
        Assert.Equal(connectionString, options.Postgres.ConnectionString);

        await using var app = ControlPlaneHostApplication.Build(builder);
        try
        {
            await app.StartAsync();

            var addresses = app.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()?.Addresses;
            var address = Assert.Single(addresses ?? []);
            using var client = new HttpClient { BaseAddress = new Uri(address) };

            var ready = await client.GetAsync("/health/ready");

            Assert.True(ready.IsSuccessStatusCode);
            Assert.Contains("\"isReady\":true", await ready.Content.ReadAsStringAsync());
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public void Prohibited_hosting_configuration_fails_during_bootstrap_before_a_server_can_start()
    {
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        builder.Configuration.Sources.Clear();
        var configuration = ValidHostConfiguration();
        configuration["urls"] = "http://0.0.0.0:5080";
        builder.Configuration.AddInMemoryCollection(configuration);

        var error = Assert.Throws<InvalidOperationException>(
            () => ControlPlaneHostApplication.Build(builder));

        Assert.Contains("URL configuration is prohibited", error.Message);
    }

    [Fact]
    public void Code_only_host_configuration_disables_json_reload()
    {
        var configuration = new ConfigurationManager();

        ControlPlaneHostConfiguration.AddSources(configuration, "Development", []);

        Assert.False(ControlPlaneHostConfiguration.HasReloadableJsonSource(configuration));
    }

    public sealed class UnconfiguredHostFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                configuration.AddInMemoryCollection(
                    new Dictionary<string, string?>
                    {
                        ["ControlPlane:Lab:Enabled"] = "false"
                    });
            });
        }

    }

    private static Dictionary<string, string?> ValidHostConfiguration() => new()
    {
        ["ControlPlane:Lab:Enabled"] = "true",
        ["ControlPlane:Lab:Topology"] = ControlPlaneConfiguration.LabTopology,
        ["ControlPlane:Identity:ServiceName"] = "armada-control-plane-lab",
        ["ControlPlane:Identity:InstanceId"] = "mac-lab-001",
        ["ControlPlane:Binding:ListenUrl"] = "http://127.0.0.1:0",
        ["ControlPlane:Binding:PublicBaseUrl"] = "http://127.0.0.1:0",
        ["ControlPlane:Postgres:ConnectionString"] =
            "Host=127.0.0.1;Port=5432;Database=armada_lab;Username=armada_lab",
        ["ControlPlane:Storage:SchemaManagement"] = "OperatorApplied",
        ["ControlPlane:Storage:Backup:RestoreEvidence:ArtifactPath"] =
            "/tmp/armada-host-test-restore-evidence.json",
        ["ControlPlane:Storage:Backup:RestoreEvidence:ContentDigest"] =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    };

    private sealed class VerifiedEvidence : IRestoreEvidenceVerifier
    {
        public Task<bool> IsVerifiedAsync(
            LocalRestoreEvidenceReference evidence,
            CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private sealed class ReachablePostgres : IPostgresReadinessProbe
    {
        public Task<bool> IsReachableAsync(CancellationToken cancellationToken) => Task.FromResult(true);
    }
}
