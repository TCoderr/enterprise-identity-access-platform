using Microsoft.Extensions.Logging;

namespace Halka.Shared;

public static class LoggingSetup
{
    /// <summary>
    /// JSON console logs with conservative categories: request-start lines and outgoing HTTP client lines are
    /// suppressed because they contain full URLs (authorization codes, one-time tokens in query strings).
    /// </summary>
    public static ILoggingBuilder AddHalkaLogging(this ILoggingBuilder logging)
    {
        logging.ClearProviders();
        logging.AddJsonConsole(options =>
        {
            options.IncludeScopes = false;
            options.UseUtcTimestamp = true;
            options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
        });
        logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning);
        logging.AddFilter("Microsoft.AspNetCore.Routing", LogLevel.Warning);
        logging.AddFilter("Microsoft.AspNetCore.Mvc", LogLevel.Warning);
        logging.AddFilter("Microsoft.AspNetCore.StaticFiles", LogLevel.Warning);
        logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Warning);
        logging.AddFilter("Microsoft.AspNetCore.DataProtection", LogLevel.Warning);
        logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
        logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);
        logging.AddFilter("OpenIddict", LogLevel.Warning);
        return logging;
    }
}
