using Halka.Iam;
using Halka.Shared;
using Microsoft.Extensions.Configuration;

if (HealthProbe.IsRequested(args))
{
    return await HealthProbe.RunAsync(new ConfigurationBuilder().AddEnvironmentVariables().Build());
}

var app = IamHost.Build(args);
await app.RunAsync();
return 0;
