using Halka.Iam.Data;
using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Halka.Iam.Pages.Admin;

public sealed class IndexModel(IamDbContext db, SessionService sessions, TimeProvider time, IOptions<CentralSessionOptions> options) : PageModel
{
    public CurrentSession Session { get; private set; } = null!;

    public int UserCount { get; private set; }

    public int ActiveSessionCount { get; private set; }

    public int ActiveGrantCount { get; private set; }

    public int PendingMailCount { get; private set; }

    public bool StepUpFresh { get; private set; }

    public int StepUpMinutes => (int)options.Value.StepUpWindow.TotalMinutes;

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        Session = HttpContext.RequireCurrentSession();
        StepUpFresh = Session.IsStepUpFresh(now, options.Value.StepUpWindow);
        UserCount = await db.Users.CountAsync(cancellationToken);
        ActiveSessionCount = await sessions.Active(now).CountAsync(cancellationToken);
        ActiveGrantCount = await db.SessionGrants.CountAsync(x => x.RevokedAt == null, cancellationToken);
        PendingMailCount = await db.OutboxMessages.CountAsync(x => x.DeliveredAt == null && x.DeadAt == null, cancellationToken);
    }
}
