using Armada.ControlPlane.Host;

var environmentName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")
    ?? Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT")
    ?? Environments.Production;
var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions
{
    Args = args,
    EnvironmentName = environmentName
});
ControlPlaneHostConfiguration.AddSources(builder.Configuration, builder.Environment.EnvironmentName, args);
var app = ControlPlaneHostApplication.Build(builder);

app.Run();

public partial class Program;

public static class ControlPlaneHostApplication
{
    public static WebApplication Build(WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = builder.Configuration.GetSection(ControlPlaneOptions.SectionName).Get<ControlPlaneOptions>()
            ?? new ControlPlaneOptions();

        ControlPlaneHostBootstrap.Configure(builder, options);

        builder.Services.AddRouting();
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton<IRestoreEvidenceVerifier, LocalRestoreEvidenceVerifier>();
        builder.Services.AddSingleton<IPostgresReadinessProbe, PostgresReadinessProbe>();
        builder.Services.AddSingleton<IControlPlaneReadiness, ControlPlaneReadiness>();

        var app = builder.Build();

        app.MapGet("/health/live", () => Results.Ok(new { status = "live" }));
        app.MapGet("/health/ready", async (IControlPlaneReadiness readiness, CancellationToken cancellationToken) =>
        {
            var report = await readiness.CheckAsync(cancellationToken);
            return report.IsReady
                ? Results.Ok(report)
                : Results.Json(report, statusCode: StatusCodes.Status503ServiceUnavailable);
        });

        return app;
    }
}
