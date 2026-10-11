using Halka.DemoClient;
using Halka.Pano;
using Halka.Shared;
using Microsoft.Extensions.Configuration;

if (HealthProbe.IsRequested(args))
{
    return await HealthProbe.RunAsync(new ConfigurationBuilder().AddEnvironmentVariables().Build());
}

var app = PanoApp.Build(args);
await app.RunAsync();
return 0;

namespace Halka.Pano
{
    /// <summary>Demo client A: a team note board that may read and add workspace notes.</summary>
    public static class PanoApp
    {
        public static readonly DemoClientDefaults Defaults = new(
            Name: "Pano",
            Slug: "pano",
            Theme: "app-pano",
            Tagline: "A small team note board. It reads and adds notes in the shared workspace on your behalf.",
            Scopes: ["openid", "profile", "email", "offline_access", "workspace.read", "workspace.write"],
            CanWrite: true);

        public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
            => DemoClientHost.Build(args, Defaults, configure);
    }
}
