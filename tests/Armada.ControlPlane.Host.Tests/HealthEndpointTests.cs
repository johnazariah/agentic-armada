using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

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
}
