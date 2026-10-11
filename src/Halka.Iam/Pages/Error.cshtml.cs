using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Halka.Iam.Pages;

/// <summary>Generic error page. It never shows exception details, paths or identifiers.</summary>
[AllowAnonymous]
[IgnoreAntiforgeryToken]
public sealed class ErrorModel : PageModel
{
    public string Heading { get; private set; } = "Something went wrong";

    public string Message { get; private set; } = "The request could not be completed. Please try again.";

    public void OnGet(int? status) => Describe(status);

    public void OnPost(int? status) => Describe(status);

    private void Describe(int? status)
    {
        (Heading, Message) = (status ?? HttpContext.Response.StatusCode) switch
        {
            StatusCodes.Status400BadRequest => ("The request was not valid", "The form may have expired. Go back, reload the page and try again."),
            StatusCodes.Status403Forbidden => ("Access denied", "Your account is not allowed to open this page."),
            StatusCodes.Status404NotFound => ("Page not found", "The page does not exist or is not available to you."),
            StatusCodes.Status429TooManyRequests => ("Too many requests", "Please wait a moment and try again."),
            StatusCodes.Status503ServiceUnavailable => ("Temporarily unavailable", "The service cannot be reached right now. Please try again shortly."),
            _ => (Heading, Message),
        };
    }
}
