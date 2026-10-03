namespace Ileva.SdkApiV3.Auth.Stores;

/// <summary>
/// Store usado quando nenhum Redis é informado: guarda os dados em memória, compartilhada por todas
/// as instâncias do processo.
///
/// Só serve para um processo único. Com vários processos (várias réplicas, vários workers) cada um
/// geraria o seu token, invalidando o dos outros — nesse caso use Redis.
/// </summary>
public sealed class InMemoryTokenStore : ITokenStore
{
    // Estático: compartilhado por todas as instâncias do processo.
    private static readonly Dictionary<string, (string Value, long ExpiresAtMs)> Items = new();
    private static readonly object Gate = new();

    /// <summary>Apaga tudo o que está guardado no processo.</summary>
    public static void Clear()
    {
        lock (Gate)
        {
            Items.Clear();
        }
    }

    public Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        lock (Gate)
        {
            return Task.FromResult(Read(key));
        }
    }

    public Task SetAsync(string key, string value, long ttlSeconds, CancellationToken cancellationToken = default)
    {
        lock (Gate)
        {
            Items[key] = (value, Environment.TickCount64 + ttlSeconds * 1000);
        }
        return Task.CompletedTask;
    }

    public Task DeleteAsync(string key, string? accessToken = null, CancellationToken cancellationToken = default)
    {
        lock (Gate)
        {
            var value = Read(key);
            if (value is null)
            {
                return Task.CompletedTask;
            }
            var token = Token.FromJson(value);
            if (accessToken is null || token is null || token.AccessToken == accessToken)
            {
                Items.Remove(key);
            }
        }
        return Task.CompletedTask;
    }

    public Task<bool> AcquireLockAsync(string key, string owner, long ttlMilliseconds, CancellationToken cancellationToken = default)
    {
        lock (Gate)
        {
            if (Read(key) is not null)
            {
                return Task.FromResult(false);
            }
            Items[key] = (owner, Environment.TickCount64 + ttlMilliseconds);
            return Task.FromResult(true);
        }
    }

    public Task ReleaseLockAsync(string key, string owner, CancellationToken cancellationToken = default)
    {
        lock (Gate)
        {
            if (Read(key) == owner)
            {
                Items.Remove(key);
            }
        }
        return Task.CompletedTask;
    }

    // Chamado sempre sob o lock: ler e gravar sem interrupção é o que torna o lock atômico no processo.
    private static string? Read(string key)
    {
        if (!Items.TryGetValue(key, out var item))
        {
            return null;
        }
        if (item.ExpiresAtMs <= Environment.TickCount64)
        {
            Items.Remove(key);
            return null;
        }
        return item.Value;
    }
}
