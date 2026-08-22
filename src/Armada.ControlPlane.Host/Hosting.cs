using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;

namespace Armada.ControlPlane.Host;

public static class ControlPlaneHostBootstrap
{
    public static void Configure(WebApplicationBuilder builder, ControlPlaneOptions options)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(options);

        var bindingFailures = HostBindingConfiguration.Validate(
            builder.Configuration,
            builder.WebHost.GetSetting(WebHostDefaults.ServerUrlsKey));
        if (!bindingFailures.IsEmpty)
        {
            throw new InvalidOperationException(string.Join(
                " ",
                bindingFailures.Select(static failure => failure.Message)));
        }

        if (!ControlPlaneConfiguration.TryGetLoopbackListenEndpoint(options, out var listenEndpoint))
        {
            throw new InvalidOperationException("The lab host requires a validated loopback listener.");
        }

        builder.WebHost.UseKestrel();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(listenEndpoint.Address, listenEndpoint.Port));
    }
}

public static class ControlPlaneHostConfiguration
{
    public static void AddSources(
        ConfigurationManager configuration,
        string environmentName,
        string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(environmentName);
        ArgumentNullException.ThrowIfNull(arguments);

        configuration.Sources.Clear();
        configuration
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
            .AddJsonFile($"appsettings.{environmentName}.json", optional: true, reloadOnChange: false)
            .AddEnvironmentVariables()
            .AddCommandLine(arguments);
    }

    public static bool HasReloadableJsonSource(ConfigurationManager configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        return configuration.Sources
            .OfType<JsonConfigurationSource>()
            .Any(static source => source.ReloadOnChange);
    }
}
