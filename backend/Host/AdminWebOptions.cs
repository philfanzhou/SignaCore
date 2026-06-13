namespace QuantumZhou.Identity.Host;

public sealed class AdminWebOptions
{
    public const string SectionName = "AdminWeb";

    public string[] AdminUsernames { get; set; } = Array.Empty<string>();
}
