using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Ileva.SdkApiV3.Auth;

/// <summary>
/// Token de acesso da API Ileva.
///
/// O formato serializado (<see cref="ToJson"/>) é o contrato gravado no cache: os SDKs de todas as
/// linguagens leem e gravam o mesmo JSON, para que serviços em linguagens diferentes compartilhem o
/// mesmo token.
/// </summary>
public sealed class Token
{
    private static readonly JsonWriterOptions WriterOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public Token(string accessToken, string tokenType, long expiresAt, bool twoFactor = false)
    {
        AccessToken = accessToken;
        TokenType = tokenType;
        ExpiresAt = expiresAt;
        TwoFactor = twoFactor;
    }

    public string AccessToken { get; }

    public string TokenType { get; }

    /// <summary>Instante de expiração, em segundos Unix.</summary>
    public long ExpiresAt { get; }

    /// <summary>Obtido com código de autenticação em dois fatores: nunca é devolvido do cache.</summary>
    public bool TwoFactor { get; }

    /// <summary>
    /// O token é considerado válido até <paramref name="refreshMarginSeconds"/> antes de expirar, para
    /// que uma requisição iniciada perto do fim da validade não chegue à API com ele já vencido.
    /// </summary>
    public bool IsValid(long nowSeconds, int refreshMarginSeconds = 0) => nowSeconds < ExpiresAt - refreshMarginSeconds;

    /// <summary>Valor pronto para o header Authorization, ex.: "Bearer eyJ...".</summary>
    public string AuthorizationHeader() => TokenType + " " + AccessToken;

    /// <param name="passwordCheck">
    /// Verificador da senha que gerou o token (veja o contrato do cache). O SDK sempre grava com ele.
    /// </param>
    public string ToJson(string? passwordCheck = null)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("access_token", AccessToken);
            writer.WriteString("token_type", TokenType);
            writer.WriteNumber("expires_at", ExpiresAt);
            if (passwordCheck is not null)
            {
                writer.WriteString("password_check", passwordCheck);
            }
            if (TwoFactor)
            {
                writer.WriteBoolean("two_factor", true);
            }
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    /// <summary>Verificador da senha gravado junto do token, ou null se não houver.</summary>
    public static string? PasswordCheckFromJson(string json)
    {
        using var document = ParseObject(json);
        return document is not null
            && document.RootElement.TryGetProperty("password_check", out var check)
            && check.ValueKind == JsonValueKind.String
                ? check.GetString()
                : null;
    }

    /// <summary>Devolve null para um valor corrompido ou em outro formato, que é tratado como cache vazio.</summary>
    public static Token? FromJson(string json)
    {
        using var document = ParseObject(json);
        if (document is null)
        {
            return null;
        }
        var root = document.RootElement;
        if (!root.TryGetProperty("access_token", out var accessToken) || accessToken.ValueKind != JsonValueKind.String
            || !root.TryGetProperty("expires_at", out var expiresAt) || expiresAt.ValueKind != JsonValueKind.Number
            || !expiresAt.TryGetInt64(out var expiresAtValue))
        {
            return null;
        }

        var tokenType = root.TryGetProperty("token_type", out var type) && type.ValueKind == JsonValueKind.String
            ? type.GetString()!
            : "Bearer";
        var twoFactor = root.TryGetProperty("two_factor", out var flag) && flag.ValueKind == JsonValueKind.True;

        return new Token(accessToken.GetString()!, tokenType, expiresAtValue, twoFactor);
    }

    /// <summary>Não expõe o token em logs e no depurador.</summary>
    public override string ToString() => $"Token {{ TokenType = {TokenType}, ExpiresAt = {ExpiresAt} }}";

    private static JsonDocument? ParseObject(string json)
    {
        try
        {
            var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                return document;
            }
            document.Dispose();
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
