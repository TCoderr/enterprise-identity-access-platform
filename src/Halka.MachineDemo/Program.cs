using Halka.MachineDemo;
using Microsoft.Extensions.Configuration;

// Machine-to-machine demo: obtains a token with the client_credentials grant and calls the Workspace API.
// Configuration: Machine:Authority, Machine:ApiBaseUrl, Machine:ClientId, Machine:ClientSecretFile (private file),
// Machine:Scopes (space separated) and the Backchannel section. The secret is read from the file, never printed.
var configuration = new ConfigurationBuilder().AddEnvironmentVariables().AddCommandLine(args).Build();
using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(60));
try
{
    var report = await MachineClient.RunAsync(configuration, cancellation.Token);
    foreach (var line in report.Lines)
    {
        Console.WriteLine(line);
    }

    return report.Succeeded ? 0 : 1;
}
catch (Exception exception)
{
    Console.Error.WriteLine($"machine demo failed: {exception.GetType().Name}: {exception.Message}");
    return 2;
}
