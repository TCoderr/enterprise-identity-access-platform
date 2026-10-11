using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Halka.Iam.Pages.Manage;

public sealed class IndexModel(SessionService sessions, TimeProvider time) : PageModel
{
    public CurrentSession Session { get; private set; } = null!;

    public int ActiveSessionCount { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        Session = HttpContext.RequireCurrentSession();
        ActiveSessionCount = await sessions.Active(time.GetUtcNow()).CountAsync(x => x.UserId == Session.UserId, cancellationToken);
    }
}
