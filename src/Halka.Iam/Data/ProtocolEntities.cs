namespace Halka.Iam.Data;

public static class ClientKind
{
    public const string Web = "web";
    public const string Machine = "machine";
    public const string Resource = "resource";

    public static readonly IReadOnlyList<string> All = [Web, Machine, Resource];
}

/// <summary>Product settings of a registered client, keyed by the OpenIddict application identifier.</summary>
public sealed class ClientSettings
{
    public Guid ApplicationId { get; set; }

    public string Kind { get; set; } = ClientKind.Web;

    public bool IsDisabled { get; set; }

    public DateTimeOffset? DisabledAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public Guid? CreatedBy { get; set; }
}

/// <summary>A previous client secret that stays valid until <see cref="NotAfter"/> (rotation grace window).</summary>
public sealed class ClientSecret
{
    public Guid Id { get; set; }

    public Guid ApplicationId { get; set; }

    /// <summary>Hash produced by the OpenIddict application manager; the clear-text secret is never stored.</summary>
    public string SecretHash { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset NotAfter { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public Guid? CreatedBy { get; set; }
}

/// <summary>
/// Links an OpenIddict authorization (the grant, root of a token family) to the central session, user and client
/// it was issued for. Ending the session revokes its grants; revoking a grant invalidates every token under it.
/// </summary>
public sealed class SessionGrant
{
    public Guid AuthorizationId { get; set; }

    public Guid SessionId { get; set; }

    public Guid UserId { get; set; }

    public Guid ApplicationId { get; set; }

    public string ClientId { get; set; } = string.Empty;

    public string Scopes { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public string? RevokedReason { get; set; }
}

/// <summary>Remembered user decision that a client may receive a set of scopes. Independent of sessions and tokens.</summary>
public sealed class Consent
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public string ClientId { get; set; } = string.Empty;

    /// <summary>Space-delimited granted scopes.</summary>
    public string Scopes { get; set; } = string.Empty;

    public DateTimeOffset GrantedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }
}

public static class ProtocolKeyUse
{
    public const string Signing = "signing";
    public const string Encryption = "encryption";
}

public static class ProtocolKeyStatus
{
    /// <summary>Signs or encrypts new tokens and validates existing ones.</summary>
    public const string Active = "active";

    /// <summary>Only validates or decrypts tokens issued earlier; signing keys stay published in the JWKS.</summary>
    public const string Retiring = "retiring";

    /// <summary>Removed after the overlap period.</summary>
    public const string Retired = "retired";

    /// <summary>Removed immediately because of suspected compromise.</summary>
    public const string Revoked = "revoked";
}

/// <summary>Token signing or encryption key pair. The private part is wrapped with Data Protection.</summary>
public sealed class ProtocolKey
{
    public Guid Id { get; set; }

    public string Use { get; set; } = string.Empty;

    public string Kid { get; set; } = string.Empty;

    public string Algorithm { get; set; } = string.Empty;

    public string Status { get; set; } = string.Empty;

    public byte[] ProtectedPrivateKey { get; set; } = [];

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? ActivatedAt { get; set; }

    public DateTimeOffset? RetiringSince { get; set; }

    /// <summary>Earliest time the key may be retired: every token it protected has expired by then.</summary>
    public DateTimeOffset? RetireNotBefore { get; set; }

    public DateTimeOffset? RetiredAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public string? Reason { get; set; }
}

public static class RevocationReason
{
    public const string SessionEnded = "session_ended";
    public const string ConsentRevoked = "consent_revoked";
    public const string ClientDisabled = "client_disabled";
    public const string UserRevoked = "user_revoked";
    public const string AdminRevoked = "admin_revoked";
    public const string RefreshReuse = "refresh_token_reuse";
    public const string KeyCompromise = "key_compromise";
}
