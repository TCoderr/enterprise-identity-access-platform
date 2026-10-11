using System.ComponentModel.DataAnnotations;
using Halka.Iam.Identity;
using Halka.Iam.Ops;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace Halka.Iam.Pages.Account;

/// <summary>Public sign-up. It can only ever create a local account with the "User" role.</summary>
[AllowAnonymous]
[EnableRateLimiting(RateLimitPolicies.Signup)]
public sealed class RegisterModel(AccountService accounts) : PageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = new();

    public IReadOnlyList<string> Errors { get; private set; } = [];

    public bool Sent { get; private set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            Errors = ModelState.Values.SelectMany(entry => entry.Errors).Select(error => error.ErrorMessage).Distinct().ToList();
            return Page();
        }

        var result = await accounts.RegisterAsync(Input.Email, Input.DisplayName, Input.Password, cancellationToken);
        if (!result.Accepted)
        {
            Errors = result.Errors;
            return Page();
        }

        Sent = true;
        return Page();
    }

    public sealed class InputModel
    {
        [Required(ErrorMessage = "Enter your name."), StringLength(100, ErrorMessage = "The name can be at most 100 characters.")]
        public string DisplayName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Enter an e-mail address."), EmailAddress(ErrorMessage = "Enter a valid e-mail address."), StringLength(254)]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Enter a password."), StringLength(256, ErrorMessage = "The password can be at most 256 characters.")]
        public string Password { get; set; } = string.Empty;
    }
}
