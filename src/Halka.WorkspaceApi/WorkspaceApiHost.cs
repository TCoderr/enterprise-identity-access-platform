using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Claims;
using Halka.Shared;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Halka.WorkspaceApi;

public sealed class WorkspaceApiOptions
{
    public const string SectionName = "Api";

    /// <summary>Issuer (identity provider origin). Tokens are validated there by introspection on every request.</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>Resource identifier of this API; tokens must be issued for this audience.</summary>
    public string Audience { get; set; } = "workspace-api";

    public string ClientId { get; set; } = "workspace-api";

    /// <summary>How recent the user's sign-in must be for the sensitive endpoint.</summary>
    public TimeSpan SensitiveFreshness { get; set; } = TimeSpan.FromMinutes(15);
}

public sealed record Note(Guid Id, string Text, string Author, DateTimeOffset CreatedAt);

public sealed record NoteInput(string? Text);

/// <summary>
/// Demo resource server. It never validates tokens locally: every request is introspected at the identity provider
/// (RFC 7662), so a revoked session, grant, user or client loses access on the very next request. When the identity
/// provider cannot be reached the API answers 503 and grants nothing (fail closed).
/// </summary>
public static class WorkspaceApiHost
{
    public const string ScopeRead = "workspace.read";
    public const string ScopeWrite = "workspace.write";
    public const string ScopeJobs = "workspace.jobs";
    private const string UnavailableItem = "halka.authorization-server-unavailable";

    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ApplicationName = typeof(WorkspaceApiHost).Assembly.GetName().Name,
        });
        builder.Logging.AddHalkaLogging();
        builder.Host.UseDefaultServiceProvider(options =>
        {
            options.ValidateScopes = true;
            options.ValidateOnBuild = true;
        });
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.AddServerHeader = false);

        var settings = builder.Configuration.GetSection(WorkspaceApiOptions.SectionName).Get<WorkspaceApiOptions>() ?? new WorkspaceApiOptions();
        var secret = SecretFile.Resolve(builder.Configuration.GetSection(WorkspaceApiOptions.SectionName), "ClientSecret")
                     ?? throw new InvalidOperationException("Api:ClientSecret (or Api:ClientSecretFile) is not configured.");
        builder.Services.Configure<WorkspaceApiOptions>(builder.Configuration.GetSection(WorkspaceApiOptions.SectionName));
        if (!builder.Services.Any(descriptor => descriptor.ServiceType == typeof(TimeProvider)))
        {
            builder.Services.AddSingleton(TimeProvider.System);
        }

        builder.Services.AddSingleton<NoteStore>();
        builder.Services.AddProblemDetails();
        builder.Services.AddOpenIddict().AddValidation(validation =>
        {
            validation.SetIssuer(new Uri(settings.Authority.TrimEnd('/') + "/", UriKind.Absolute));
            validation.AddAudiences(settings.Audience);
            validation.UseIntrospection().SetClientId(settings.ClientId).SetClientSecret(secret);
            validation.UseSystemNetHttp();
            validation.UseAspNetCore();
        });
        builder.Services.AddHalkaBackchannel(builder.Configuration);
        builder.Services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        builder.Services.AddAuthorization();
        configure?.Invoke(builder);

        var app = builder.Build();
        app.UseHalkaSecurityHeaders();
        app.Use(FailClosedWhenAuthorizationServerIsUnavailable);
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/health/live", () => Results.Ok(new { status = "Healthy" })).AllowAnonymous();

        app.MapGet("/notes", (ClaimsPrincipal user, NoteStore store) =>
                RequireScope(user, ScopeRead) ?? Results.Ok(store.All()))
            .RequireAuthorization();

        app.MapPost("/notes", (ClaimsPrincipal user, NoteInput input, NoteStore store, TimeProvider time) =>
            {
                if (RequireScope(user, ScopeWrite) is { } denied)
                {
                    return denied;
                }

                // Writing is an end-user action: a token issued to a client on its own behalf has no user.
                if (IsClientToken(user))
                {
                    return Forbidden("user-required", "This operation requires a token issued for an end user.");
                }

                var text = input.Text?.Trim();
                if (string.IsNullOrEmpty(text) || text.Length > 280)
                {
                    return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Invalid note", detail: "The note text must be 1 to 280 characters.");
                }

                return Results.Created("/notes", store.Add(text, user.GetClaim(Claims.Subject)!, time.GetUtcNow()));
            })
            .RequireAuthorization();

        app.MapGet("/notes/sensitive", (ClaimsPrincipal user, NoteStore store, TimeProvider time, Microsoft.Extensions.Options.IOptions<WorkspaceApiOptions> options) =>
            {
                if (RequireScope(user, ScopeRead) is { } denied)
                {
                    return denied;
                }

                // Assurance comes from signed-in state reported by the identity provider, not from the caller.
                var usedMfa = user.GetClaims(Claims.AuthenticationMethodReference).Contains("mfa", StringComparer.Ordinal);
                var fresh = long.TryParse(user.GetClaim(Claims.AuthenticationTime), NumberStyles.None, CultureInfo.InvariantCulture, out var authTime)
                            && time.GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(authTime) <= options.Value.SensitiveFreshness;
                if (!usedMfa || !fresh)
                {
                    return Forbidden("step-up-required", "A recent sign-in with multi-factor authentication is required.");
                }

                return Results.Ok(store.All().Select(note => note with { Text = $"[sensitive] {note.Text}" }));
            })
            .RequireAuthorization();

        app.MapGet("/jobs/status", (ClaimsPrincipal user, TimeProvider time) =>
            {
                if (RequireScope(user, ScopeJobs) is { } denied)
                {
                    return denied;
                }

                return IsClientToken(user)
                    ? Results.Ok(new { status = "idle", checkedAt = time.GetUtcNow(), caller = user.GetClaim(Claims.Subject) })
                    : Forbidden("client-required", "This operation is reserved for machine clients.");
            })
            .RequireAuthorization();

        return app;
    }

    /// <summary>
    /// The validation handler reports an unreachable identity provider either as an exception or as a
    /// "server_error" failure. Both become 503 with Retry-After; neither is ever treated as an invalid token (401)
    /// or as success.
    /// </summary>
    private static async Task FailClosedWhenAuthorizationServerIsUnavailable(HttpContext http, RequestDelegate next)
    {
        try
        {
            await next(http);
        }
        catch (Exception exception) when (!http.Response.HasStarted && IsUnavailable(exception))
        {
            http.Items[UnavailableItem] = true;
        }

        if (http.Items.ContainsKey(UnavailableItem) && !http.Response.HasStarted)
        {
            await WriteUnavailableAsync(http);
            return;
        }

        if (http.Response.HasStarted || http.Response.StatusCode is not (StatusCodes.Status400BadRequest or StatusCodes.Status401Unauthorized or StatusCodes.Status500InternalServerError))
        {
            return;
        }

        // Distinguish "the token could not be checked" from "the token was checked and is not acceptable".
        var result = await http.AuthenticateAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        var error = result.Properties?.GetString(OpenIddictValidationAspNetCoreConstants.Properties.Error);
        if (error is Errors.ServerError or Errors.TemporarilyUnavailable)
        {
            await WriteUnavailableAsync(http);
        }
        else if (error is not null && http.Response.StatusCode != StatusCodes.Status401Unauthorized)
        {
            // The identity provider refused the token itself (for example an ID token or an unsupported token
            // type). For the caller of this API that is simply an invalid bearer token.
            http.Response.Clear();
            http.Response.StatusCode = StatusCodes.Status401Unauthorized;
            http.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
            http.Response.Headers.CacheControl = "no-store";
        }
    }

    private static Task WriteUnavailableAsync(HttpContext http)
    {
        http.Response.Clear();
        http.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        http.Response.Headers.RetryAfter = "5";
        http.Response.Headers.CacheControl = "no-store";
        return http.Response.WriteAsJsonAsync(
            new ProblemDetails
            {
                Type = "https://halka.localhost/problems/authorization-server-unavailable",
                Status = StatusCodes.Status503ServiceUnavailable,
                Title = "Authorization server unavailable",
                Detail = "The token could not be verified because the identity provider cannot be reached. No access was granted.",
            },
            options: null,
            contentType: "application/problem+json");
    }

    private static bool IsUnavailable(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is HttpRequestException or TaskCanceledException or TimeoutException or System.Net.Sockets.SocketException
                or OpenIddictExceptions.ProtocolException)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsClientToken(ClaimsPrincipal user)
        => string.Equals(user.GetClaim(Claims.Subject), user.GetClaim(Claims.ClientId), StringComparison.Ordinal);

    private static IResult? RequireScope(ClaimsPrincipal user, string scope)
        => user.HasScope(scope) ? null : InsufficientScope(scope);

    private static IResult InsufficientScope(string scope) => new ProblemWithChallenge(
        new ProblemDetails
        {
            Type = "https://halka.localhost/problems/insufficient-scope",
            Status = StatusCodes.Status403Forbidden,
            Title = "Insufficient scope",
            Detail = $"The access token does not include the '{scope}' scope.",
        },
        $"Bearer error=\"insufficient_scope\", scope=\"{scope}\"");

    private static IResult Forbidden(string type, string detail) => new ProblemWithChallenge(
        new ProblemDetails
        {
            Type = $"https://halka.localhost/problems/{type}",
            Status = StatusCodes.Status403Forbidden,
            Title = "Forbidden",
            Detail = detail,
        },
        null);

    private sealed class ProblemWithChallenge(ProblemDetails problem, string? challenge) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            httpContext.Response.StatusCode = problem.Status ?? StatusCodes.Status403Forbidden;
            if (challenge is not null)
            {
                httpContext.Response.Headers.WWWAuthenticate = challenge;
            }

            return httpContext.Response.WriteAsJsonAsync(problem, options: null, contentType: "application/problem+json");
        }
    }
}

/// <summary>In-memory demo data. The API has no store of its own; only its authorization behaviour matters here.</summary>
public sealed class NoteStore
{
    private readonly ConcurrentQueue<Note> _notes = new();

    public IReadOnlyList<Note> All() => [.. _notes];

    public Note Add(string text, string author, DateTimeOffset createdAt)
    {
        var note = new Note(Guid.NewGuid(), text, author, createdAt);
        _notes.Enqueue(note);
        while (_notes.Count > 200 && _notes.TryDequeue(out _))
        {
        }

        return note;
    }
}
