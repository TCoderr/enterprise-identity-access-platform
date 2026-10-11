using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Halka.TestKit;

/// <summary>
/// A loopback TCP forwarder placed between one host under test and its database. Interrupting it closes every
/// open connection and refuses new ones, which is what the host sees when its database goes away; resuming makes
/// the same address reachable again. Only the stack that owns the relay is affected.
/// </summary>
public sealed class TcpRelay : IAsyncDisposable
{
    private readonly string _targetHost;
    private readonly int _targetPort;
    private readonly ConcurrentDictionary<Guid, (TcpClient Inbound, TcpClient Outbound)> _connections = new();
    private readonly object _gate = new();
    private TcpListener? _listener;
    private CancellationTokenSource? _stop;
    private Task _acceptLoop = Task.CompletedTask;

    private TcpRelay(string targetHost, int targetPort, int port)
    {
        _targetHost = targetHost;
        _targetPort = targetPort;
        Port = port;
    }

    public int Port { get; }

    public static TcpRelay Start(string targetHost, int targetPort)
    {
        int port;
        using (var probe = new TcpListener(IPAddress.Loopback, 0))
        {
            probe.Start();
            port = ((IPEndPoint)probe.LocalEndpoint).Port;
        }

        var relay = new TcpRelay(targetHost, targetPort, port);
        relay.Resume();
        return relay;
    }

    /// <summary>Starts accepting connections (again).</summary>
    public void Resume()
    {
        lock (_gate)
        {
            if (_listener is not null)
            {
                return;
            }

            _stop = new CancellationTokenSource();
            _listener = new TcpListener(IPAddress.Loopback, Port);
            _listener.Start();
            _acceptLoop = AcceptAsync(_listener, _stop.Token);
        }
    }

    /// <summary>Refuses new connections and closes the open ones.</summary>
    public async Task InterruptAsync()
    {
        Task loop;
        lock (_gate)
        {
            if (_listener is null)
            {
                return;
            }

            _stop!.Cancel();
            _listener.Stop();
            _listener = null;
            loop = _acceptLoop;
        }

        await loop;
        foreach (var (id, pair) in _connections)
        {
            pair.Inbound.Dispose();
            pair.Outbound.Dispose();
            _connections.TryRemove(id, out _);
        }
    }

    private async Task AcceptAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient inbound;
            try
            {
                inbound = await listener.AcceptTcpClientAsync(cancellationToken);
            }
            catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                return;
            }

            _ = PumpAsync(inbound, cancellationToken);
        }
    }

    private async Task PumpAsync(TcpClient inbound, CancellationToken cancellationToken)
    {
        var id = Guid.NewGuid();
        var outbound = new TcpClient { NoDelay = true };
        inbound.NoDelay = true;
        _connections[id] = (inbound, outbound);
        try
        {
            await outbound.ConnectAsync(_targetHost, _targetPort, cancellationToken);
            var up = inbound.GetStream().CopyToAsync(outbound.GetStream(), cancellationToken);
            var down = outbound.GetStream().CopyToAsync(inbound.GetStream(), cancellationToken);
            await Task.WhenAny(up, down);
        }
        catch (Exception exception) when (exception is OperationCanceledException or IOException or SocketException or ObjectDisposedException)
        {
        }
        finally
        {
            inbound.Dispose();
            outbound.Dispose();
            _connections.TryRemove(id, out _);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await InterruptAsync();
        _stop?.Dispose();
    }
}
