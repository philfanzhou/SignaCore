namespace SignaCore.Database.Entity;

/// <summary>A canonical browser redirect registration owned by an application.</summary>
public class AppRedirectUriEntity
{
    public Guid Id { get; set; }
    public Guid AppRegistrationId { get; set; }
    public RedirectUriKind Kind { get; set; }
    public string CanonicalUri { get; set; } = string.Empty;
    public AppRegistrationEntity AppRegistration { get; set; } = null!;
}
