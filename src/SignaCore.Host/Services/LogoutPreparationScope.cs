namespace SignaCore.Host.Services;

// Set only on the new scope owned by logout preparation, before any context is resolved. Provider
// diagnostics can contain raw exception/connection values; this scope uses bounded service logs.
internal sealed class LogoutPreparationScope
{
    public bool IsActive { get; set; }
}
