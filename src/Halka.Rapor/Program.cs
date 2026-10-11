using Halka.DemoClient;
using Halka.Rapor;
using Halka.Shared;
using Microsoft.Extensions.Configuration;

if (HealthProbe.IsRequested(args))
{
    return await HealthProbe.RunAsync(new ConfigurationBuilder().AddEnvironmentVariables().Build());
}

var app = RaporApp.Build(args);
await app.RunAsync();
return 0;

namespace Halka.Rapor
{
    /// <summary>Demo client B: a read-only reporting view. It is not allowed the write scope or the e-mail claim.</summary>
    public static class RaporApp
    {
        public static readonly DemoClientDefaults Defaults = new(
            Name: "Rapor",
            Slug: "rapor",
            Theme: "app-rapor",
            Tagline: "A read-only reporting view of the shared workspace. It can read notes but is not permitted to add any.",
            Scopes: ["openid", "profile", "offline_access", "workspace.read"],
            CanWrite: false);

        public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
            => DemoClientHost.Build(args, Defaults, configure);
    }
}
