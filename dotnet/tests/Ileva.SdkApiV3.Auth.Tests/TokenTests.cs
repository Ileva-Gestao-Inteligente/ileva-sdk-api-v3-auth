using Xunit;

namespace Ileva.SdkApiV3.Auth.Tests;

public sealed class TokenTests
{
    [Fact]
    public void EValidoAteAMargemDeRenovacao()
    {
        var token = new Token("t", "Bearer", 1000);

        Assert.True(token.IsValid(699, 300));
        Assert.False(token.IsValid(700, 300));
        Assert.True(token.IsValid(999));
        Assert.False(token.IsValid(1000));
    }

    [Fact]
    public void MontaOHeaderDeAutorizacao()
    {
        Assert.Equal("Bearer abc", new Token("abc", "Bearer", 1).AuthorizationHeader());
    }

    [Fact]
    public void SerializaNoFormatoDoContrato()
    {
        Assert.Equal(
            """{"access_token":"a/b+c","token_type":"Bearer","expires_at":1790000000}""",
            new Token("a/b+c", "Bearer", 1790000000).ToJson());
        Assert.Equal(
            """{"access_token":"a","token_type":"Bearer","expires_at":1,"password_check":"pbkdf2-sha256$1$AQ==$AQ==","two_factor":true}""",
            new Token("a", "Bearer", 1, twoFactor: true).ToJson("pbkdf2-sha256$1$AQ==$AQ=="));
    }

    [Fact]
    public void LeOJsonDoContrato()
    {
        var token = Token.FromJson("""{"access_token":"a","token_type":"Bearer","expires_at":123,"password_check":"x","two_factor":true}""")!;

        Assert.Equal("a", token.AccessToken);
        Assert.Equal("Bearer", token.TokenType);
        Assert.Equal(123, token.ExpiresAt);
        Assert.True(token.TwoFactor);
        Assert.Equal("x", Token.PasswordCheckFromJson("""{"access_token":"a","expires_at":1,"password_check":"x"}"""));
    }

    [Fact]
    public void TokenTypeAusenteViraBearer()
    {
        Assert.Equal("Bearer", Token.FromJson("""{"access_token":"a","expires_at":1}""")!.TokenType);
    }

    [Theory]
    [InlineData("")]
    [InlineData("nao-e-json")]
    [InlineData("[]")]
    [InlineData("""{"expires_at":1}""")]
    [InlineData("""{"access_token":"a"}""")]
    [InlineData("""{"access_token":1,"expires_at":1}""")]
    [InlineData("""{"access_token":"a","expires_at":"1"}""")]
    [InlineData("""{"access_token":"a","expires_at":1.5}""")]
    public void ValorForaDoFormatoDevolveNull(string json)
    {
        Assert.Null(Token.FromJson(json));
    }

    [Fact]
    public void TwoFactorSoVaiComTrueExato()
    {
        Assert.False(Token.FromJson("""{"access_token":"a","expires_at":1,"two_factor":"true"}""")!.TwoFactor);
        Assert.False(Token.FromJson("""{"access_token":"a","expires_at":1,"two_factor":1}""")!.TwoFactor);
    }

    [Fact]
    public void ToStringNaoExpoeOToken()
    {
        Assert.DoesNotContain("segredo-do-token", new Token("segredo-do-token", "Bearer", 1).ToString());
    }
}
