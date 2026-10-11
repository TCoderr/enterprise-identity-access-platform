namespace Halka.Iam.Identity;

public static class Roles
{
    public const string User = "User";
    public const string SecurityAdmin = "SecurityAdmin";
    public const string ApplicationAdmin = "ApplicationAdmin";
    public const string PlatformAdmin = "PlatformAdmin";

    public static readonly IReadOnlyList<string> All = [User, SecurityAdmin, ApplicationAdmin, PlatformAdmin];

    public static readonly IReadOnlyList<string> Administrative = [SecurityAdmin, ApplicationAdmin, PlatformAdmin];
}

public sealed class IamOptions
{
    public const string SectionName = "Iam";

    /// <summary>Public HTTPS origin of the identity provider; also the token issuer.</summary>
    public string PublicOrigin { get; set; } = string.Empty;

    public TimeSpan EmailConfirmationLifetime { get; set; } = TimeSpan.FromHours(24);

    public TimeSpan PasswordResetLifetime { get; set; } = TimeSpan.FromMinutes(30);

    public Uri PublicOriginUri => new(PublicOrigin.TrimEnd('/') + "/", UriKind.Absolute);

    public string Link(string pathAndQuery) => PublicOrigin.TrimEnd('/') + pathAndQuery;
}
