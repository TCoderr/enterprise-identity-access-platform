using Halka.Iam.Data;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Halka.Iam.Ops;

public sealed class DatabaseHealthCheck(IamDbContext db, ILogger<DatabaseHealthCheck> logger) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            if (await db.Database.CanConnectAsync(timeout.Token))
            {
                return HealthCheckResult.Healthy();
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
        }

        // The probe runs every few seconds; an outage it sees is the moment to drop the dead pooled connections.
        StorePool.DropIdleConnections(db, logger);
        return HealthCheckResult.Unhealthy();
    }
}

public static class HealthEndpoints
{
    /// <summary>Liveness never touches dependencies; readiness requires them. Neither exposes details.</summary>
    public static void MapHalkaHealth(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false, ResponseWriter = WriteStatus })
            .AllowAnonymous().ExcludeFromDescription();
        endpoints.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready"), ResponseWriter = WriteStatus })
            .AllowAnonymous().ExcludeFromDescription();
    }

    private static Task WriteStatus(HttpContext http, HealthReport report)
        => http.Response.WriteAsJsonAsync(new { status = report.Status.ToString() });
}
