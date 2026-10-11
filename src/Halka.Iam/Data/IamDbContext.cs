using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using OpenIddict.EntityFrameworkCore.Models;

namespace Halka.Iam.Data;

public sealed class IamDbContext(DbContextOptions<IamDbContext> options)
    : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>(options)
{
    public DbSet<UserSession> UserSessions => Set<UserSession>();

    public DbSet<OneTimeToken> OneTimeTokens => Set<OneTimeToken>();

    public DbSet<OutboxMessage> OutboxMessages => Set<OutboxMessage>();

    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    public DbSet<DataMarker> DataMarkers => Set<DataMarker>();

    public DbSet<ClientSettings> ClientSettings => Set<ClientSettings>();

    public DbSet<ClientSecret> ClientSecrets => Set<ClientSecret>();

    public DbSet<SessionGrant> SessionGrants => Set<SessionGrant>();

    public DbSet<Consent> Consents => Set<Consent>();

    public DbSet<ProtocolKey> ProtocolKeys => Set<ProtocolKey>();

    public DbSet<UserMfa> UserMfa => Set<UserMfa>();

    public DbSet<RecoveryCode> RecoveryCodes => Set<RecoveryCode>();

    public DbSet<MfaChallenge> MfaChallenges => Set<MfaChallenge>();

    public DbSet<OpenIddictEntityFrameworkCoreApplication<Guid>> Applications => Set<OpenIddictEntityFrameworkCoreApplication<Guid>>();

    public DbSet<OpenIddictEntityFrameworkCoreAuthorization<Guid>> Authorizations => Set<OpenIddictEntityFrameworkCoreAuthorization<Guid>>();

    public DbSet<OpenIddictEntityFrameworkCoreToken<Guid>> Tokens => Set<OpenIddictEntityFrameworkCoreToken<Guid>>();

    public DbSet<OpenIddictEntityFrameworkCoreScope<Guid>> Scopes => Set<OpenIddictEntityFrameworkCoreScope<Guid>>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>(entity =>
        {
            entity.ToTable("users");
            entity.Property(x => x.DisplayName).HasMaxLength(100);
        });
        builder.Entity<ApplicationRole>().ToTable("roles");
        builder.Entity<IdentityUserRole<Guid>>().ToTable("user_roles");
        builder.Entity<IdentityUserClaim<Guid>>().ToTable("user_claims");
        builder.Entity<IdentityUserLogin<Guid>>().ToTable("user_logins");
        builder.Entity<IdentityUserToken<Guid>>().ToTable("user_tokens");
        builder.Entity<IdentityRoleClaim<Guid>>().ToTable("role_claims");

        builder.Entity<UserSession>(entity =>
        {
            entity.ToTable("user_sessions");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Id).ValueGeneratedNever();
            entity.Property(x => x.Amr).HasMaxLength(64);
            entity.Property(x => x.RevokedReason).HasMaxLength(64);
            entity.Property(x => x.ClientLabel).HasMaxLength(64);
            entity.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(x => new { x.UserId, x.RevokedAt });
        });

        builder.Entity<OneTimeToken>(entity =>
        {
            entity.ToTable("one_time_tokens");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Id).ValueGeneratedNever();
            entity.Property(x => x.Purpose).HasMaxLength(32);
            entity.HasIndex(x => x.TokenHash).IsUnique();
            entity.HasIndex(x => new { x.UserId, x.Purpose });
            entity.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<OutboxMessage>(entity =>
        {
            entity.ToTable("outbox_messages");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Id).ValueGeneratedNever();
            entity.Property(x => x.Kind).HasMaxLength(64);
            entity.Property(x => x.LeaseOwner).HasMaxLength(64);
            entity.Property(x => x.LastErrorCode).HasMaxLength(64);
            entity.HasIndex(x => new { x.DeliveredAt, x.DeadAt, x.AvailableAt });
        });

        builder.Entity<AuditEvent>(entity =>
        {
            entity.ToTable("audit_events");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Id).UseIdentityAlwaysColumn();
            entity.Property(x => x.ActorType).HasMaxLength(32);
            entity.Property(x => x.ActorId).HasMaxLength(64);
            entity.Property(x => x.Action).HasMaxLength(64);
            entity.Property(x => x.TargetType).HasMaxLength(32);
            entity.Property(x => x.TargetId).HasMaxLength(128);
            entity.Property(x => x.Outcome).HasMaxLength(16);
            entity.Property(x => x.CorrelationId).HasMaxLength(64);
            entity.Property(x => x.Reason).HasMaxLength(200);
            entity.HasIndex(x => x.OccurredAt);
            entity.HasIndex(x => x.ActorId);
            entity.HasIndex(x => x.TargetId);
        });

        builder.Entity<ClientSettings>(entity =>
        {
            entity.ToTable("client_settings");
            entity.HasKey(x => x.ApplicationId);
            entity.Property(x => x.ApplicationId).ValueGeneratedNever();
            entity.Property(x => x.Kind).HasMaxLength(16);
            entity.HasOne<OpenIddictEntityFrameworkCoreApplication<Guid>>().WithMany().HasForeignKey(x => x.ApplicationId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<ClientSecret>(entity =>
        {
            entity.ToTable("client_secrets");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Id).ValueGeneratedNever();
            entity.Property(x => x.SecretHash).HasMaxLength(512);
            entity.HasIndex(x => new { x.ApplicationId, x.NotAfter });
            entity.HasOne<OpenIddictEntityFrameworkCoreApplication<Guid>>().WithMany().HasForeignKey(x => x.ApplicationId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<SessionGrant>(entity =>
        {
            entity.ToTable("session_grants");
            entity.HasKey(x => x.AuthorizationId);
            entity.Property(x => x.AuthorizationId).ValueGeneratedNever();
            entity.Property(x => x.ClientId).HasMaxLength(100);
            entity.Property(x => x.Scopes).HasMaxLength(1000);
            entity.Property(x => x.RevokedReason).HasMaxLength(64);
            entity.HasIndex(x => x.SessionId);
            entity.HasIndex(x => new { x.UserId, x.ClientId });
            entity.HasIndex(x => x.ApplicationId);
            entity.HasOne<OpenIddictEntityFrameworkCoreAuthorization<Guid>>().WithMany().HasForeignKey(x => x.AuthorizationId).OnDelete(DeleteBehavior.Cascade);
            entity.HasOne<UserSession>().WithMany().HasForeignKey(x => x.SessionId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<Consent>(entity =>
        {
            entity.ToTable("consents");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Id).ValueGeneratedNever();
            entity.Property(x => x.ClientId).HasMaxLength(100);
            entity.Property(x => x.Scopes).HasMaxLength(1000);
            entity.HasIndex(x => new { x.UserId, x.ClientId }).IsUnique().HasFilter("revoked_at IS NULL");
            entity.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<ProtocolKey>(entity =>
        {
            entity.ToTable("protocol_keys");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Id).ValueGeneratedNever();
            entity.Property(x => x.Use).HasMaxLength(16);
            entity.Property(x => x.Kid).HasMaxLength(64);
            entity.Property(x => x.Algorithm).HasMaxLength(32);
            entity.Property(x => x.Status).HasMaxLength(16);
            entity.Property(x => x.Reason).HasMaxLength(200);
            entity.HasIndex(x => x.Kid).IsUnique();

            // At most one active key per use, enforced by the database.
            entity.HasIndex(x => x.Use).IsUnique().HasFilter("status = 'active'").HasDatabaseName("ux_protocol_keys_one_active_per_use");
        });

        builder.Entity<UserMfa>(entity =>
        {
            entity.ToTable("user_mfa");
            entity.HasKey(x => x.UserId);
            entity.Property(x => x.UserId).ValueGeneratedNever();
            entity.Property(x => x.Status).HasMaxLength(16);
            entity.HasOne<ApplicationUser>().WithOne().HasForeignKey<UserMfa>(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<RecoveryCode>(entity =>
        {
            entity.ToTable("recovery_codes");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Id).ValueGeneratedNever();
            entity.HasIndex(x => new { x.UserId, x.CodeHash }).IsUnique();
            entity.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<MfaChallenge>(entity =>
        {
            entity.ToTable("mfa_challenges");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Id).ValueGeneratedNever();
            entity.Property(x => x.Purpose).HasMaxLength(16);
            entity.HasIndex(x => x.ExpiresAt);
            entity.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<DataMarker>(entity =>
        {
            entity.ToTable("data_markers");
            entity.HasKey(x => x.Key);
            entity.Property(x => x.Key).HasMaxLength(64);
            entity.Property(x => x.Value).HasMaxLength(256);
        });
    }
}

/// <summary>Used only by "dotnet ef" at design time; it never connects to a database.</summary>
public sealed class IamDesignTimeDbContextFactory : IDesignTimeDbContextFactory<IamDbContext>
{
    public IamDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<IamDbContext>();
        IamDbContextConfiguration.Configure(options, "Host=design-time.invalid;Database=design;Username=design;Password=design");
        return new IamDbContext(options.Options);
    }
}

public static class IamDbContextConfiguration
{
    public static void Configure(DbContextOptionsBuilder options, string connectionString)
    {
        options.UseNpgsql(connectionString, npgsql => npgsql.MigrationsAssembly(typeof(IamDbContext).Assembly.GetName().Name));
        options.UseSnakeCaseNamingConvention();
        options.UseOpenIddict<Guid>();
    }
}
