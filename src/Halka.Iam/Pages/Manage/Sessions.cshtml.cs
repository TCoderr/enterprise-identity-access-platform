using Halka.Iam.Audit;
using Halka.Iam.Revocation;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Halka.Iam.Pages.Manage;

public sealed class SessionsModel(SessionService sessions, RevocationService revocation, TimeProvider time) : PageModel
{
    public IReadOnlyList<Item> Items { get; private set; } = [];

    [TempData]
    public string? Result { get; set; }

    public async Task OnGetAsync(CancellationToken cancellationToken) => await LoadAsync(cancellationToken);

    public async Task<IActionResult> OnPostRevokeAsync(Guid id, CancellationToken cancellationToken)
    {
        var current = HttpContext.RequireCurrentSession();

        // Ownership is checked on the server: an identifier of another user's session behaves like an unknown one.
        var owned = await sessions.Active(time.GetUtcNow()).AnyAsync(x => x.Id == id && x.UserId == current.UserId, cancellationToken);
        if (!owned)
        {
            return NotFound();
        }

        await revocation.EndSessionAsync(id, id == current.Id ? SessionEndReason.Logout : SessionEndReason.UserRevoked, AuditActor.User, current.UserId.ToString(), cancellationToken);
        if (id == current.Id)
        {
            await HttpContext.SignOutIfPresentAsync();
            Response.Headers["Clear-Site-Data"] = "\"cache\"";
            return LocalRedirect("/account/login?notice=signed-out");
        }

        Result = "The session was ended. Applications opened from it lose access on their next request.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostRevokeAllAsync(CancellationToken cancellationToken)
    {
        var current = HttpContext.RequireCurrentSession();
        await revocation.EndAllSessionsAsync(current.UserId, SessionEndReason.LogoutAll, AuditActor.User, current.UserId.ToString(), null, cancellationToken);
        await HttpContext.SignOutIfPresentAsync();
        Response.Headers["Clear-Site-Data"] = "\"cache\"";
        return LocalRedirect("/account/login?notice=signed-out");
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
        var current = HttpContext.RequireCurrentSession();
        Items = await sessions.Active(time.GetUtcNow())
            .Where(x => x.UserId == current.UserId)
            .OrderByDescending(x => x.LastSeenAt)
            .Select(x => new Item(x.Id, x.ClientLabel, x.AuthTime, x.LastSeenAt, x.Amr, x.Id == current.Id))
            .ToListAsync(cancellationToken);
    }

    public sealed record Item(Guid Id, string ClientLabel, DateTimeOffset AuthTime, DateTimeOffset LastSeenAt, string Amr, bool IsCurrent);
}
