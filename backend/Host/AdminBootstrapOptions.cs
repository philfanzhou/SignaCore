namespace QuantumZhou.Identity.Host;

public sealed class AdminBootstrapOptions
{
    public const string SectionName = "AdminBootstrap";

    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;
}
