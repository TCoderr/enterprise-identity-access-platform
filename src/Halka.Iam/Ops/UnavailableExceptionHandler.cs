using Halka.Iam.Data;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Halka.Iam.Ops;

/// <summary>
/// Turns a lost database connection into "503 Service Unavailable" instead of a generic error. The request fails
/// closed: no session is honoured and no cookie is removed while state cannot be checked. The response is a static
/// document so it does not depend on the unavailable store.
/// </summary>
public sealed class UnavailableExceptionHandler(ILogger<UnavailableExceptionHandler> logger) : IExceptionHandler
{
    private const string Html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Temporarily unavailable · Halka ID</title>
        <link rel="stylesheet" href="/assets/site.css">
        </head>
        <body class="app-halka">
        <main id="main" class="page page--medium">
        <h1>Temporarily unavailable</h1>
        <p>Halka ID cannot reach its data store right now. Nothing was changed. Please try again shortly.</p>
        </main>
        </body>
        </html>
        """;

    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        if (!IsStoreUnavailable(exception))
        {
            return false;
        }

        logger.LogError("The data store is unavailable ({ErrorType}); the request was rejected with 503.", exception.GetType().Name);
        StorePool.DropIdleConnections(httpContext.RequestServices.GetService<IamDbContext>(), logger);
        var response = httpContext.Response;
        response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        response.Headers.RetryAfter = "5";
        response.Headers.CacheControl = "no-store";
        // The exception middleware has already switched the request to the error path; the feature has the original.
        var path = new PathString(httpContext.Features.Get<IExceptionHandlerPathFeature>()?.Path ?? httpContext.Request.Path.Value);
        var interactive = path.StartsWithSegments("/connect/authorize") || path.StartsWithSegments("/connect/endsession");
        if (path.StartsWithSegments("/connect") && !interactive)
        {
            // Back-channel protocol requests get a standard OAuth error object, so clients can parse it.
            await response.WriteAsJsonAsync(
                new { error = "temporarily_unavailable", error_description = "The authorization server cannot reach its data store." },
                cancellationToken);
        }
        else if (path.StartsWithSegments("/api"))
        {
            await response.WriteAsJsonAsync(
                new ProblemDetails { Status = 503, Title = "Service Unavailable", Detail = "The service cannot reach its data store." },
                options: null,
                contentType: "application/problem+json",
                cancellationToken);
        }
        else
        {
            response.ContentType = "text/html; charset=utf-8";
            await response.WriteAsync(Html, cancellationToken);
        }

        return true;
    }

    public static bool IsStoreUnavailable(Exception? exception) => Halka.Shared.StoreFailures.IsUnavailable(exception);
}

public static class StorePool
{
    /// <summary>
    /// Connections that were idle in the pool when the database went away are dead as well. Whoever notices an
    /// outage (a request, the readiness probe, the outbox worker) drops them, so requests that arrive after the
    /// database is back get fresh connections instead of each failing once on a stale one.
    /// </summary>
    public static void DropIdleConnections(IamDbContext? db, ILogger logger)
    {
        try
        {
            if (db?.Database.GetDbConnection() is NpgsqlConnection connection)
            {
                NpgsqlConnection.ClearPool(connection);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or ObjectDisposedException or NpgsqlException)
        {
            logger.LogWarning("The connection pool could not be cleared ({ErrorType}).", exception.GetType().Name);
        }
    }
}
