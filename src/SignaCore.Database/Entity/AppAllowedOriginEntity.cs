namespace SignaCore.Database.Entity;

/// <summary>A canonical browser Origin registered for one Public application.</summary>
public class AppAllowedOriginEntity
{
    public Guid Id { get; set; }
    public Guid AppRegistrationId { get; set; }
    public string CanonicalOrigin { get; set; } = string.Empty;
    public AppRegistrationEntity AppRegistration { get; set; } = null!;
}
