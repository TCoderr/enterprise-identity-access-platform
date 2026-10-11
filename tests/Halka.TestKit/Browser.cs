using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using AngleSharp;
using AngleSharp.Dom;
using AngleSharp.Html.Dom;

namespace Halka.TestKit;

/// <summary>A fetched document together with the redirect chain that led to it.</summary>
public sealed class Page(Uri url, HttpStatusCode status, string body, HttpResponseMessage response, IReadOnlyList<Uri> visited)
{
    private IDocument? _document;

    public Uri Url { get; } = url;

    public HttpStatusCode Status { get; } = status;

    public string Body { get; } = body;

    public HttpResponseMessage Response { get; } = response;

    /// <summary>Every URL requested for this navigation, in order (the last entry is <see cref="Url"/>).</summary>
    public IReadOnlyList<Uri> Visited { get; } = visited;

    public IDocument Document => _document ??= BrowsingContext.New(Configuration.Default)
        .OpenAsync(request => request.Content(Body).Address(Url.ToString())).GetAwaiter().GetResult();

    public string Text => Document.Body?.TextContent ?? string.Empty;

    public string? Header(string name)
        => Response.Headers.TryGetValues(name, out var values) || Response.Content.Headers.TryGetValues(name, out values)
            ? string.Join(", ", values)
            : null;

    public IElement? Find(string selector) => Document.QuerySelector(selector);
}

/// <summary>
/// HTTP user agent for integration tests: real TLS (test CA trust only), a real cookie jar, manual redirect
/// following and real HTML form submission (including anti-forgery fields). It does not model SameSite; cross-site
/// cookie behaviour is covered by the real-browser tests.
/// </summary>
public sealed class Browser : IDisposable
{
    private readonly X509Certificate2 _authority;
    private readonly IPAddress? _sourceAddress;

    /// <param name="sourceAddress">
    /// Loopback address the requests come from (for example 127.0.0.21). The server sees it as the remote address,
    /// which lets a test act as a separate network client.
    /// </param>
    public Browser(X509Certificate2 authority, CookieContainer? cookies = null, IPAddress? sourceAddress = null)
    {
        _authority = authority;
        _sourceAddress = sourceAddress;
        Cookies = cookies ?? new CookieContainer();
        var handler = new SocketsHttpHandler
        {
            UseCookies = true,
            CookieContainer = Cookies,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectCallback = ConnectAsync,
        };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) => Validate(certificate, errors);
        Http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };
        Http.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) HalkaTestBrowser Chrome/140.0");
    }

    public CookieContainer Cookies { get; }

    public HttpClient Http { get; }

    /// <summary>A second user agent that starts with a copy of this one's cookies (a "captured cookie" replay).</summary>
    public Browser CloneWithCookies()
    {
        var copy = new CookieContainer();
        foreach (Cookie cookie in Cookies.GetAllCookies())
        {
            copy.Add(new Cookie(cookie.Name, cookie.Value, cookie.Path, cookie.Domain)
            {
                Secure = cookie.Secure,
                HttpOnly = cookie.HttpOnly,
                Expires = cookie.Expires,
            });
        }

        return new Browser(_authority, copy, _sourceAddress);
    }

    public Cookie? Cookie(string origin, string name)
        => Cookies.GetCookies(new Uri(origin)).FirstOrDefault(cookie => cookie.Name == name);

    public Task<Page> GetAsync(string url, bool follow = true)
        => SendAsync(() => new HttpRequestMessage(HttpMethod.Get, url), follow);

    /// <summary>Submits a form of <paramref name="page"/> the way a browser would, overriding the given fields.</summary>
    public Task<Page> SubmitAsync(
        Page page,
        string formSelector,
        IReadOnlyDictionary<string, string>? fields = null,
        bool follow = true,
        Func<string, bool>? omit = null)
    {
        var form = page.Document.QuerySelector(formSelector) as IHtmlFormElement
                   ?? throw new InvalidOperationException($"Form '{formSelector}' was not found on {page.Url.AbsolutePath}.");
        var values = new List<KeyValuePair<string, string>>();
        foreach (var element in form.Elements)
        {
            switch (element)
            {
                case IHtmlInputElement input when !string.IsNullOrEmpty(input.Name):
                    if (input.Type is "submit" or "button" or "image" or "file" or "reset")
                    {
                        continue;
                    }

                    if (input.Type is "checkbox" or "radio" && !input.IsChecked)
                    {
                        continue;
                    }

                    values.Add(new(input.Name, input.Value ?? string.Empty));
                    break;
                case IHtmlTextAreaElement area when !string.IsNullOrEmpty(area.Name):
                    values.Add(new(area.Name, area.Value ?? string.Empty));
                    break;
                case IHtmlSelectElement select when !string.IsNullOrEmpty(select.Name):
                    values.AddRange(select.SelectedOptions.Select(option => new KeyValuePair<string, string>(select.Name!, option.Value)));
                    break;
            }
        }

        if (fields is not null)
        {
            foreach (var (name, value) in fields)
            {
                values.RemoveAll(pair => pair.Key == name);
                values.Add(new(name, value));
            }
        }

        if (omit is not null)
        {
            values.RemoveAll(pair => omit(pair.Key));
        }

        var rawAction = form.GetAttribute("action");
        var action = string.IsNullOrEmpty(rawAction) ? page.Url.ToString() : new Uri(page.Url, rawAction).ToString();
        if (string.Equals(form.Method, "get", StringComparison.OrdinalIgnoreCase))
        {
            var query = string.Join('&', values.Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
            return GetAsync(new UriBuilder(action) { Query = query }.Uri.ToString(), follow);
        }

        return PostFormAsync(action, values, follow);
    }

    public Task<Page> PostFormAsync(string url, IEnumerable<KeyValuePair<string, string>> values, bool follow = true)
    {
        var captured = values.ToList();
        return SendAsync(() => new HttpRequestMessage(HttpMethod.Post, url) { Content = new FormUrlEncodedContent(captured) }, follow);
    }

    public async Task<Page> SendAsync(Func<HttpRequestMessage> requestFactory, bool follow = true)
    {
        var visited = new List<Uri>();
        var request = requestFactory();
        for (var hop = 0; hop < 20; hop++)
        {
            visited.Add(request.RequestUri!);
            var response = await Http.SendAsync(request);
            var redirect = (int)response.StatusCode is 301 or 302 or 303 or 307 or 308;
            if (!follow || !redirect || response.Headers.Location is null)
            {
                var body = await response.Content.ReadAsStringAsync();
                return new Page(request.RequestUri!, response.StatusCode, body, response, visited);
            }

            var next = new Uri(request.RequestUri!, response.Headers.Location);
            var preserveMethod = (int)response.StatusCode is 307 or 308;
            var previous = request;
            request = new HttpRequestMessage(preserveMethod ? previous.Method : HttpMethod.Get, next);
            response.Dispose();
        }

        throw new InvalidOperationException($"Redirect loop detected: {string.Join(" -> ", visited.Select(uri => uri.GetLeftPart(UriPartial.Path)))}");
    }

    private async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            if (_sourceAddress is not null)
            {
                socket.Bind(new IPEndPoint(_sourceAddress, 0));
            }

            // Browsers resolve "*.localhost" to loopback (RFC 6761); the test user agent does the same.
            if (context.DnsEndPoint.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
            {
                await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, context.DnsEndPoint.Port), cancellationToken);
            }
            else
            {
                await socket.ConnectAsync(context.DnsEndPoint, cancellationToken);
            }

            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private bool Validate(System.Security.Cryptography.X509Certificates.X509Certificate? certificate, SslPolicyErrors errors)
    {
        if (certificate is null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
        {
            return false;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(_authority);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        using var leaf = new X509Certificate2(certificate);
        return chain.Build(leaf);
    }

    public void Dispose() => Http.Dispose();
}
