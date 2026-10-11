using Halka.Shared;
using Halka.WorkspaceApi;
using Microsoft.Extensions.Configuration;

if (HealthProbe.IsRequested(args))
{
    return await HealthProbe.RunAsync(new ConfigurationBuilder().AddEnvironmentVariables().Build(), "/health/live");
}

var app = WorkspaceApiHost.Build(args);
await app.RunAsync();
return 0;
