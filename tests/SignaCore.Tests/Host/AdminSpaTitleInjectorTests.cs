using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host;

public class AdminSpaTitleInjectorTests
{
    private const string Template = "<html><head><title>__APP_TITLE__</title></head><body></body></html>";

    [Fact]
    public void Inject_ReplacesTitlePlaceholder()
    {
        var result = AdminSpaTitleInjector.Inject(Template, "my-project");

        Assert.Contains("<title>my-project</title>", result);
        Assert.DoesNotContain("<title>__APP_TITLE__</title>", result);
    }

    [Fact]
    public void Inject_InjectsWindowGlobalBeforeHeadClose()
    {
        var result = AdminSpaTitleInjector.Inject(Template, "my-project");

        Assert.Contains("<script>window.__APP_TITLE__ = 'my-project';</script></head>", result);
    }

    [Fact]
    public void Inject_EscapesSingleQuotes()
    {
        var result = AdminSpaTitleInjector.Inject(Template, "it's-a-project");

        Assert.Contains("window.__APP_TITLE__ = 'it\\'s-a-project';", result);
    }
}
