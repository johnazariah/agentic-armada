using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

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

        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(listenEndpoint.Address, listenEndpoint.Port));
    }
}
