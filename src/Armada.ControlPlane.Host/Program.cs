using Armada.ControlPlane.Host;

var builder = WebApplication.CreateBuilder(args);
var options = builder.Configuration.GetSection(ControlPlaneOptions.SectionName).Get<ControlPlaneOptions>()
    ?? new ControlPlaneOptions();

ControlPlaneHostBootstrap.Configure(builder, options);
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

app.Run();

public partial class Program;
