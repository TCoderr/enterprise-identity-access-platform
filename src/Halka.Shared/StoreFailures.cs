using System.Data.Common;
using System.Net.Sockets;

namespace Halka.Shared;

public static class StoreFailures
{
    /// <summary>
    /// True when an exception means "the data store cannot be reached right now" (connection refused or lost,
    /// timeout, server shutting down) rather than a defect. Callers answer such requests with 503 and change
    /// nothing, because no state could be checked.
    /// </summary>
    public static bool IsUnavailable(Exception? exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is DbException { IsTransient: true } or TimeoutException or SocketException)
            {
                return true;
            }
        }

        return false;
    }
}
