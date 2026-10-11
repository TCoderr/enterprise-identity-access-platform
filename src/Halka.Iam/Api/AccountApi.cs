using Halka.Iam.Audit;
using Halka.Iam.Data;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Halka.Iam.Api;

public sealed record SessionSummary(
    string SessionId,
    DateTimeOffset AuthTime,
    IReadOnlyList<string> Amr,
    DateTimeOffset ExpiresAt,
    bool StepUpFresh,
    IReadOnlyList<string> Roles);

/// <summary>Small JSON product API (ProblemDetails errors). Protocol endpoints are not part of it.</summary>
public static class AccountApi
{
    public static void MapAccountApi(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/account")
            .RequireAuthorization(policy => policy.AddAuthenticationSchemes(SessionDefaults.Scheme).RequireAuthenticatedUser())
            .WithTags("Account");

        group.MapGet("/session", Ok<SessionSummary> (HttpContext http, TimeProvider time, IOptions<CentralSessionOptions> options) =>
        {
            var session = http.RequireCurrentSession();
            return TypedResults.Ok(new SessionSummary(
                session.Id.ToString("N")[..8],
                session.AuthTime,
                session.Amr,
                session.AbsoluteExpiresAt,
                session.IsStepUpFresh(time.GetUtcNow(), options.Value.StepUpWindow),
                session.Roles));
        }).WithName("GetCurrentSession");

        group.MapDelete("/sessions/{id:guid}", async Task<Results<NoContent, NotFound, ProblemHttpResult>> (
            Guid id,
            HttpContext http,
            IAntiforgery antiforgery,
            IamDbContext db,
            RevocationService revocation,
            CancellationToken cancellationToken) =>
        {
            if (!await antiforgery.IsRequestValidAsync(http))
            {
                return TypedResults.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Invalid anti-forgery token.");
            }

            // Ownership is decided on the server: a session id that belongs to someone else is indistinguishable from an unknown id.
            var session = http.RequireCurrentSession();
            var owned = await db.UserSessions.AnyAsync(x => x.Id == id && x.UserId == session.UserId && x.RevokedAt == null, cancellationToken);
            if (!owned)
            {
                return TypedResults.NotFound();
            }

            await revocation.EndSessionAsync(id, SessionEndReason.UserRevoked, AuditActor.User, session.UserId.ToString(), cancellationToken);
            return TypedResults.NoContent();
        }).WithName("RevokeOwnSession");
    }
}
