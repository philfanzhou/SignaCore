using System.Reflection;
using Microsoft.Extensions.Primitives;
using SignaCore.Host.Http;
using Xunit;

namespace SignaCore.Tests.Host.Http;

/// <summary>
/// Pins the hosted login page language negotiation (ADR 0006): any <c>zh</c>/<c>zh-*</c> range
/// renders Simplified Chinese, everything else — including a missing, strictly unparseable, or
/// out-of-range header — renders English.
/// </summary>
public class LoginPageLanguageNegotiatorTests
{
    [Theory]
    [InlineData("zh-CN")]
    [InlineData("zh")]
    [InlineData("zh-TW")]
    [InlineData("ZH-cn")]
    [InlineData("zh-Hans-CN,zh;q=0.9,en;q=0.8")]
    [InlineData("fr, zh;q=0.5")]
    [InlineData("en;q=0.4, zh-CN;q=0.6")]
    [InlineData("zh-CN;q=1")]
    public void ChineseRangesSelectSimplifiedChinese(string header)
    {
        Assert.Equal(LoginPageLanguage.SimplifiedChinese, LoginPageLanguageNegotiator.Negotiate(header));
    }

    [Theory]
    [InlineData("en-US")]
    [InlineData("*")]
    [InlineData("zh;q=0")]
    [InlineData("en-US,en;q=0.9,zh-CN;q=0.8")]
    [InlineData("garbage;zh")]
    [InlineData("zh-CN;q=abc, en")]
    [InlineData("zh-CN;q=1.5")]
    [InlineData("fr")]
    [InlineData("fr, de;q=0.5")]
    [InlineData("zho")]
    [InlineData("zhx-CN")]
    [InlineData("en, zh")]
    [InlineData("*, zh;q=0.9")]
    [InlineData("")]
    public void EveryOtherHeaderSelectsEnglish(string header)
    {
        Assert.Equal(LoginPageLanguage.English, LoginPageLanguageNegotiator.Negotiate(header));
    }

    [Fact]
    public void MissingHeaderSelectsEnglish()
    {
        Assert.Equal(LoginPageLanguage.English, LoginPageLanguageNegotiator.Negotiate(StringValues.Empty));
    }

    [Fact]
    public void EqualQualitiesKeepTheHeaderOrder()
    {
        Assert.Equal(
            LoginPageLanguage.SimplifiedChinese,
            LoginPageLanguageNegotiator.Negotiate("zh;q=0.8, en;q=0.8"));
        Assert.Equal(
            LoginPageLanguage.English,
            LoginPageLanguageNegotiator.Negotiate("en;q=0.8, zh;q=0.8"));
    }

    [Fact]
    public void SeveralHeaderValuesAreNegotiatedTogether()
    {
        Assert.Equal(
            LoginPageLanguage.SimplifiedChinese,
            LoginPageLanguageNegotiator.Negotiate(new StringValues(["fr;q=0.9", "zh-CN"])));
        Assert.Equal(
            LoginPageLanguage.English,
            LoginPageLanguageNegotiator.Negotiate(new StringValues(["zh-CN", "garbage;zh"])));
    }

    [Fact]
    public void EveryLanguageDefinesEveryText()
    {
        foreach (var text in new[] { LoginPageText.English, LoginPageText.SimplifiedChinese })
        {
            foreach (var property in typeof(LoginPageText).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                         .Where(property => property.PropertyType == typeof(string)))
            {
                var value = (string?)property.GetValue(text);
                Assert.False(string.IsNullOrWhiteSpace(value), property.Name);
                // The texts are written into the page as they are, so none may carry markup.
                Assert.DoesNotContain('<', value!);
                Assert.DoesNotContain('>', value);
                Assert.DoesNotContain('&', value);
                Assert.DoesNotContain('"', value);
            }
        }

        Assert.Equal("en", LoginPageText.English.HtmlLang);
        Assert.Equal("zh-CN", LoginPageText.SimplifiedChinese.HtmlLang);
    }
}
