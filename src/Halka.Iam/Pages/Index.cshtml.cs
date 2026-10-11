using Halka.Iam.Sessions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Halka.Iam.Pages;

[AllowAnonymous]
public sealed class IndexModel : PageModel
{
    public IActionResult OnGet()
        => HttpContext.GetCurrentSession() is null ? Page() : LocalRedirect("/manage");
}
