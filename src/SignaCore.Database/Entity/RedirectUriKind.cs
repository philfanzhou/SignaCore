namespace SignaCore.Database.Entity;

/// <summary>The browser flow that may use a registered redirect URI.</summary>
public enum RedirectUriKind
{
    Redirect = 0,
    PostLogout = 1
}
